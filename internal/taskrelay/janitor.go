package taskrelay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// JanitorConfig is the idle janitor's operator-owned configuration. The
// janitor retires agent Sandboxes no proxy replica has seen in use for
// IdleSeconds. It holds no broker token and no credential: an API-server token
// to list the proxy's Pods and to list and delete Sandboxes in Namespaces.
type JanitorConfig struct {
	// Namespaces are the opted-in tenant namespaces whose Sandboxes may be retired.
	Namespaces  []string `json:"namespaces"`
	IdleSeconds int64    `json:"idleSeconds"`
	// DryRun logs what would be deleted and deletes nothing.
	DryRun bool `json:"dryRun"`
	// DeleteConcurrency is how many deletes are in flight at once. There is
	// no cap on how many a pass deletes: it pages through every Sandbox.
	DeleteConcurrency int `json:"deleteConcurrency"`
	// ListPageSize is the page size for every list (the API's continue tokens).
	ListPageSize int `json:"listPageSize"`
	// ProxyNamespace and ProxyLabels find every proxy replica; AdminPort is
	// each replica's activity listener.
	ProxyNamespace    string            `json:"proxyNamespace"`
	ProxyLabels       map[string]string `json:"proxyLabels"`
	AdminPort         int               `json:"adminPort"`
	SandboxAPIVersion string            `json:"sandboxAPIVersion"`
	Kubernetes        KubernetesConfig  `json:"kubernetes"`
}

var labelValue = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?)?$`)
var labelKey = regexp.MustCompile(`^([a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?/)?[A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?$`)

// LoadJanitorConfig reads and validates a janitor configuration file.
func LoadJanitorConfig(path string) (JanitorConfig, error) {
	var c JanitorConfig
	b, err := readBoundedFile(path, 1<<20)
	if err != nil {
		return c, errConfig
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		return c, errConfig
	}
	return c, c.validate()
}

func (c JanitorConfig) validate() error {
	// Bounds are sanity checks, not capacity limits: concurrency up to the API
	// server's own scale, and pages up to what one response should carry.
	if len(c.Namespaces) == 0 || c.IdleSeconds < 60 || c.DeleteConcurrency < 1 || c.DeleteConcurrency > 10000 ||
		c.ListPageSize < 1 || c.ListPageSize > 10000 || !dnsLabel.MatchString(c.ProxyNamespace) || len(c.ProxyLabels) == 0 ||
		c.AdminPort < 1 || c.AdminPort > 65535 || !apiVersionPattern.MatchString(c.SandboxAPIVersion) || !strings.Contains(c.SandboxAPIVersion, "/") ||
		c.Kubernetes.CAFile == "" || c.Kubernetes.ReviewerTokenFile == "" {
		return errConfig
	}
	seen := map[string]bool{}
	for _, ns := range c.Namespaces {
		if !dnsLabel.MatchString(ns) || seen[ns] || ns == c.ProxyNamespace {
			return errConfig
		}
		seen[ns] = true
	}
	for k, v := range c.ProxyLabels {
		if !labelKey.MatchString(k) || !labelValue.MatchString(v) {
			return errConfig
		}
	}
	u, e := url.Parse(c.Kubernetes.APIURL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errConfig
	}
	return nil
}

// errJanitorDoubt means the pass deleted nothing because it could not be sure.
var errJanitorDoubt = errors.New("janitor: not every proxy replica answered for long enough; nothing deleted")

type janitor struct {
	config JanitorConfig
	client *http.Client
	admin  *http.Client
	out    io.Writer
	now    func() time.Time
	// replicaURL builds a replica's activity URL; tests point it at fakes.
	replicaURL func(podIP string) string
	// backoff is the wait before retrying a throttled request.
	backoff func(attempt int, retryAfter string) time.Duration
}

// RunJanitor makes one pass: read every proxy replica's activity, then delete
// every Sandbox in the tenant namespaces that none has seen for IdleSeconds.
func RunJanitor(ctx context.Context, c JanitorConfig, out io.Writer) error {
	if e := c.validate(); e != nil {
		return e
	}
	t, e := clientTLS(c.Kubernetes.CAFile, "")
	if e != nil {
		return e
	}
	j := &janitor{config: c, out: out, now: time.Now,
		client: &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: t, Proxy: nil, MaxResponseHeaderBytes: 8192,
			MaxIdleConnsPerHost: c.DeleteConcurrency}, CheckRedirect: func(*http.Request, []*http.Request) error { return errDenied }},
		admin: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil, MaxResponseHeaderBytes: 8192},
			CheckRedirect: func(*http.Request, []*http.Request) error { return errDenied }},
		backoff: defaultBackoff}
	j.replicaURL = func(ip string) string {
		return "http://" + net.JoinHostPort(ip, strconv.Itoa(c.AdminPort)) + ActivityPath
	}
	return j.pass(ctx)
}

func defaultBackoff(attempt int, retryAfter string) time.Duration {
	if s, e := strconv.Atoi(retryAfter); e == nil && s > 0 && s <= 60 {
		return time.Duration(s) * time.Second
	}
	d := time.Duration(1<<min(attempt, 6)) * 250 * time.Millisecond
	return d
}

func (j *janitor) log(event string, fields map[string]any) {
	fields["event"] = event
	fields["component"] = "gatehouse-janitor"
	b, _ := json.Marshal(fields)
	_, _ = j.out.Write(append(b, '\n'))
}

func (j *janitor) pass(ctx context.Context) error {
	now := j.now()
	cutoff := now.Add(-time.Duration(j.config.IdleSeconds) * time.Second)
	lastSeen, e := j.activity(ctx, cutoff)
	if e != nil {
		j.log("janitor_pass", map[string]any{"deleted": 0, "dryRun": j.config.DryRun, "error": e.Error()})
		return e
	}
	var idle []sandbox
	total := 0
	for _, ns := range j.config.Namespaces {
		boxes, e := j.sandboxes(ctx, ns)
		if e != nil {
			j.log("janitor_pass", map[string]any{"deleted": 0, "dryRun": j.config.DryRun, "error": "list sandboxes: " + e.Error()})
			return e
		}
		total += len(boxes)
		for _, s := range boxes {
			// Too young, already leaving, or used through any replica since the cutoff: kept.
			if s.DeletionTimestamp != "" || s.Created.IsZero() || s.Created.After(cutoff) || lastSeen[s.UID].After(cutoff) {
				continue
			}
			idle = append(idle, s)
		}
	}
	deleted, e := j.delete(ctx, idle, lastSeen)
	fields := map[string]any{"sandboxes": total, "idle": len(idle), "deleted": deleted, "dryRun": j.config.DryRun}
	if e != nil {
		fields["error"] = e.Error()
	}
	j.log("janitor_pass", fields)
	return e
}

// activity reads every proxy replica's report and returns, per Sandbox UID,
// the latest use any replica saw. It is all or nothing: a replica that does
// not answer, or one started after the cutoff (it cannot vouch for the whole
// idle window), means doubt, and nothing is deleted.
func (j *janitor) activity(ctx context.Context, cutoff time.Time) (map[string]time.Time, error) {
	selector := make([]string, 0, len(j.config.ProxyLabels))
	for k, v := range j.config.ProxyLabels {
		selector = append(selector, k+"="+v)
	}
	sort.Strings(selector)
	type replicaPod struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Status struct {
			Phase string `json:"phase"`
			PodIP string `json:"podIP"`
		} `json:"status"`
	}
	var replicas []replicaPod
	if e := j.list(ctx, "/api/v1/namespaces/"+url.PathEscape(j.config.ProxyNamespace)+"/pods", strings.Join(selector, ","), func(raw json.RawMessage) error {
		var page []replicaPod
		if e := json.Unmarshal(raw, &page); e != nil {
			return e
		}
		replicas = append(replicas, page...)
		return nil
	}); e != nil {
		return nil, fmt.Errorf("list proxy replicas: %w", e)
	}
	seen := map[string]time.Time{}
	answered := 0
	for _, r := range replicas {
		if r.Status.Phase == "Succeeded" || r.Status.Phase == "Failed" {
			continue
		}
		ip, e := netipString(r.Status.PodIP)
		if e != nil {
			return nil, errJanitorDoubt
		}
		report, e := j.replica(ctx, ip)
		if e != nil || report.ReplicaStarted.IsZero() || report.ReplicaStarted.After(cutoff) {
			return nil, errJanitorDoubt
		}
		answered++
		for _, p := range report.Pods {
			if p.OwnerUID != "" && p.LastSeen.After(seen[p.OwnerUID]) {
				seen[p.OwnerUID] = p.LastSeen
			}
		}
	}
	if answered == 0 {
		return nil, errJanitorDoubt
	}
	return seen, nil
}

func netipString(s string) (string, error) {
	ip := net.ParseIP(s)
	if ip == nil || ip.IsUnspecified() {
		return "", errDenied
	}
	return ip.String(), nil
}

func (j *janitor) replica(ctx context.Context, ip string) (ActivityReport, error) {
	var report ActivityReport
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, j.replicaURL(ip), nil)
	if e != nil {
		return report, e
	}
	resp, e := j.admin.Do(req)
	if e != nil {
		return report, e
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return report, errDenied
	}
	e = json.NewDecoder(io.LimitReader(resp.Body, 256<<20)).Decode(&report)
	return report, e
}

type sandbox struct {
	Namespace, Name, UID, DeletionTimestamp string
	Created                                 time.Time
}

func (j *janitor) sandboxes(ctx context.Context, ns string) ([]sandbox, error) {
	var out []sandbox
	path := "/apis/" + j.config.SandboxAPIVersion + "/namespaces/" + url.PathEscape(ns) + "/sandboxes"
	e := j.list(ctx, path, "", func(raw json.RawMessage) error {
		var items []struct {
			Metadata struct {
				Name              string    `json:"name"`
				Namespace         string    `json:"namespace"`
				UID               string    `json:"uid"`
				CreationTimestamp time.Time `json:"creationTimestamp"`
				DeletionTimestamp string    `json:"deletionTimestamp"`
			} `json:"metadata"`
		}
		if e := json.Unmarshal(raw, &items); e != nil {
			return e
		}
		for _, it := range items {
			m := it.Metadata
			if m.Namespace != ns || m.UID == "" || m.Name == "" {
				return errDenied
			}
			out = append(out, sandbox{Namespace: ns, Name: m.Name, UID: m.UID, DeletionTimestamp: m.DeletionTimestamp, Created: m.CreationTimestamp})
		}
		return nil
	})
	return out, e
}

// list pages through a collection, handing each page's items to add.
func (j *janitor) list(ctx context.Context, path, selector string, add func(json.RawMessage) error) error {
	next := ""
	for {
		query := url.Values{"limit": {strconv.Itoa(j.config.ListPageSize)}}
		if selector != "" {
			query.Set("labelSelector", selector)
		}
		if next != "" {
			query.Set("continue", next)
		}
		var page struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items json.RawMessage `json:"items"`
		}
		status, body, e := j.request(ctx, http.MethodGet, path+"?"+query.Encode(), nil)
		if e != nil {
			return e
		}
		if status != http.StatusOK || json.Unmarshal(body, &page) != nil {
			return fmt.Errorf("list %s: status %d", path, status)
		}
		if len(page.Items) > 0 && string(page.Items) != "null" {
			if e := add(page.Items); e != nil {
				return e
			}
		}
		if next = page.Metadata.Continue; next == "" {
			return nil
		}
	}
}

// request sends one API request, retrying with backoff while the API server
// throttles (429, including priority and fairness). Any other failure returns.
func (j *janitor) request(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	token, e := readBoundedFile(j.config.Kubernetes.ReviewerTokenFile, 32<<10)
	if e != nil || strings.TrimSpace(string(token)) == "" {
		return 0, nil, errDenied
	}
	endpoint := strings.TrimRight(j.config.Kubernetes.APIURL, "/") + path
	for attempt := 0; ; attempt++ {
		req, e := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
		if e != nil {
			return 0, nil, e
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, e := j.client.Do(req)
		if e != nil {
			return 0, nil, e
		}
		b, e := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
		_ = resp.Body.Close()
		if e != nil {
			return 0, nil, e
		}
		if resp.StatusCode != http.StatusTooManyRequests {
			return resp.StatusCode, b, nil
		}
		select {
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		case <-time.After(j.backoff(attempt, resp.Header.Get("Retry-After"))):
		}
	}
}

// delete removes the idle Sandboxes, DeleteConcurrency at a time, each by UID
// precondition so a Sandbox recreated under the same name is never touched. A
// Sandbox already gone or changed (404, 409) is skipped; any other failure
// stops the pass.
func (j *janitor) delete(ctx context.Context, idle []sandbox, lastSeen map[string]time.Time) (int, error) {
	if j.config.DryRun {
		for _, s := range idle {
			j.log("sandbox_would_delete", map[string]any{"namespace": s.Namespace, "name": s.Name, "uid": s.UID, "lastSeen": lastSeen[s.UID]})
		}
		return 0, nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	work := make(chan sandbox)
	var mu sync.Mutex
	var first error
	deleted := 0
	var wg sync.WaitGroup
	for range min(j.config.DeleteConcurrency, max(len(idle), 1)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for s := range work {
				body, _ := json.Marshal(map[string]any{"kind": "DeleteOptions", "apiVersion": "v1",
					"preconditions": map[string]any{"uid": s.UID}, "propagationPolicy": "Background"})
				path := "/apis/" + j.config.SandboxAPIVersion + "/namespaces/" + url.PathEscape(s.Namespace) + "/sandboxes/" + url.PathEscape(s.Name)
				status, _, e := j.request(ctx, http.MethodDelete, path, body)
				mu.Lock()
				switch {
				case e == nil && (status == http.StatusOK || status == http.StatusAccepted):
					deleted++
					j.log("sandbox_deleted", map[string]any{"namespace": s.Namespace, "name": s.Name, "uid": s.UID, "lastSeen": lastSeen[s.UID]})
				case e == nil && (status == http.StatusNotFound || status == http.StatusConflict):
				default:
					if first == nil {
						if e == nil {
							e = fmt.Errorf("delete sandbox: status %d", status)
						}
						first = e
						cancel()
					}
				}
				mu.Unlock()
			}
		}()
	}
	for _, s := range idle {
		select {
		case work <- s:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(work)
	wg.Wait()
	return deleted, first
}
