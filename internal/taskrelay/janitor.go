package taskrelay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	// ReplicaConcurrency is how many proxy replicas are read at once (default
	// 32), so a large fleet is read well inside the Job's deadline.
	ReplicaConcurrency int `json:"replicaConcurrency,omitempty"`
	// ProxyNamespace and ProxyLabels find every proxy replica; AdminPort is
	// each replica's activity listener.
	ProxyNamespace    string            `json:"proxyNamespace"`
	ProxyLabels       map[string]string `json:"proxyLabels"`
	AdminPort         int               `json:"adminPort"`
	SandboxAPIVersion string            `json:"sandboxAPIVersion"`
	Kubernetes        KubernetesConfig  `json:"kubernetes"`
	// ProxyAutoscaler and ProxyDeployment, in ProxyNamespace, name the
	// proxy's HorizontalPodAutoscaler and Deployment. A replica removed by a
	// scale-down takes its history with it, so a pass holds while either
	// changed the replica set within IdleSeconds: the autoscaler's
	// status.lastScaleTime, or the Deployment's Progressing condition's
	// lastUpdateTime (a direct edit of its replicas). Either may be empty.
	ProxyAutoscaler string `json:"proxyAutoscaler,omitempty"`
	ProxyDeployment string `json:"proxyDeployment,omitempty"`
}

var dnsSubdomain = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
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
		c.ReplicaConcurrency < 0 || c.ReplicaConcurrency > 10000 ||
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
	for _, name := range []string{c.ProxyAutoscaler, c.ProxyDeployment} {
		if name != "" && !dnsSubdomain.MatchString(name) {
			return errConfig
		}
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

func (j *janitor) replicaConcurrency() int {
	if j.config.ReplicaConcurrency == 0 {
		return 32
	}
	return j.config.ReplicaConcurrency
}

// errJanitorDoubt means the pass deleted nothing because a proxy replica did
// not answer: a fault, so the run fails.
var errJanitorDoubt = errors.New("janitor: a proxy replica did not report its activity; nothing deleted")

// janitorHold is an expected pause: the pass deletes nothing, logs why and
// succeeds, so a failed run always means a fault.
type janitorHold struct{ reason string }

func (h janitorHold) Error() string { return "janitor: holding: " + h.reason }

type janitor struct {
	config JanitorConfig
	client *http.Client
	admin  *http.Client
	out    io.Writer
	now    func() time.Time
	// replicaURL builds a replica's URL for an activity path; tests point it
	// at fakes.
	replicaURL func(podIP, path string) string
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
		admin: &http.Client{Timeout: 2 * brokerRequestTimeout, Transport: &http.Transport{Proxy: nil, MaxResponseHeaderBytes: 8192},
			CheckRedirect: func(*http.Request, []*http.Request) error { return errDenied }},
		backoff: defaultBackoff}
	j.replicaURL = func(ip, path string) string {
		return "http://" + net.JoinHostPort(ip, strconv.Itoa(c.AdminPort)) + path
	}
	return j.pass(ctx)
}

// defaultBackoff waits at least the server's Retry-After plus up to as much
// again, or else a full-jitter exponential delay, so many throttled workers
// do not retry in step.
func defaultBackoff(attempt int, retryAfter string) time.Duration {
	if s, e := strconv.Atoi(retryAfter); e == nil && s > 0 && s <= 60 {
		d := time.Duration(s) * time.Second
		return d + rand.N(d) // #nosec G404 -- retry jitter, not a secret
	}
	return rand.N(time.Duration(1<<min(attempt, 6)) * 250 * time.Millisecond) // #nosec G404 -- retry jitter, not a secret
}

func (j *janitor) log(event string, fields map[string]any) {
	fields["event"] = event
	fields["component"] = "gatehouse-janitor"
	b, _ := json.Marshal(fields)
	_, _ = j.out.Write(append(b, '\n'))
}

// pass returns nil when it held on purpose; the held reason is logged.
func (j *janitor) pass(ctx context.Context) error {
	now := j.now()
	cutoff := now.Add(-time.Duration(j.config.IdleSeconds) * time.Second)
	// With every replica's report durable, a replica's coming or going loses
	// nothing, so the scale holds apply only to replica-local reports.
	lastSeen, durable, young, e := j.activity(ctx, cutoff)
	if e == nil && !durable {
		if e = j.scaledSince(ctx, cutoff); e == nil && young {
			e = janitorHold{"proxy_replica_young"}
		}
	}
	if hold, ok := e.(janitorHold); ok {
		j.log("janitor_pass", map[string]any{"deleted": 0, "dryRun": j.config.DryRun, "held": hold.reason})
		return nil
	}
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
	fields := map[string]any{"sandboxes": total, "idle": len(idle), "deleted": deleted, "dryRun": j.config.DryRun, "durable": durable}
	if e != nil {
		fields["error"] = e.Error()
	}
	j.log("janitor_pass", fields)
	return e
}

// scaledSince holds the pass while the proxy's replica set changed after the
// cutoff: a removed replica's history is gone. A failed read is a fault.
func (j *janitor) scaledSince(ctx context.Context, cutoff time.Time) error {
	ns := "/namespaces/" + url.PathEscape(j.config.ProxyNamespace)
	if name := j.config.ProxyAutoscaler; name != "" {
		var hpa struct {
			Status struct {
				LastScaleTime *time.Time `json:"lastScaleTime"`
			} `json:"status"`
		}
		if e := j.get(ctx, "/apis/autoscaling/v2"+ns+"/horizontalpodautoscalers/"+url.PathEscape(name), &hpa); e != nil {
			return fmt.Errorf("read proxy autoscaler: %w", e)
		}
		if t := hpa.Status.LastScaleTime; t != nil && t.After(cutoff) {
			return janitorHold{"proxy_autoscaled"}
		}
	}
	if name := j.config.ProxyDeployment; name != "" {
		var deployment struct {
			Status struct {
				Conditions []struct {
					Type           string    `json:"type"`
					LastUpdateTime time.Time `json:"lastUpdateTime"`
				} `json:"conditions"`
			} `json:"status"`
		}
		if e := j.get(ctx, "/apis/apps/v1"+ns+"/deployments/"+url.PathEscape(name), &deployment); e != nil {
			return fmt.Errorf("read proxy deployment: %w", e)
		}
		for _, c := range deployment.Status.Conditions {
			if c.Type == "Progressing" && c.LastUpdateTime.After(cutoff) {
				return janitorHold{"proxy_deployment_changed"}
			}
		}
	}
	return nil
}

// get reads one object; anything but 200 is an error.
func (j *janitor) get(ctx context.Context, path string, into any) error {
	status, body, e := j.request(ctx, http.MethodGet, path, nil)
	if e != nil {
		return e
	}
	if status != http.StatusOK {
		return fmt.Errorf("status %d", status)
	}
	return json.Unmarshal(body, into)
}

// activity reads every proxy replica's report and returns, per Sandbox UID,
// the latest use any replica saw; whether every report was durable; and
// whether any replica started after the cutoff (on its own it cannot vouch
// for the whole idle window). It is all or nothing: a replica that does not
// answer, or reports a retention shorter than the idle time, is a fault, and
// nothing is deleted.
func (j *janitor) activity(ctx context.Context, cutoff time.Time) (map[string]time.Time, bool, bool, error) {
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
		return nil, false, false, fmt.Errorf("list proxy replicas: %w", e)
	}
	var live []replicaPod
	for _, r := range replicas {
		if r.Status.Phase != "Succeeded" && r.Status.Phase != "Failed" {
			live = append(live, r)
		}
	}
	if len(live) == 0 {
		return nil, false, false, errJanitorDoubt
	}
	// One replica, the first by name, answers with the broker's durable view
	// merged in; the rest answer with their own activity only, which the
	// durable view does not yet hold. Reads run ReplicaConcurrency at a time;
	// any failure is doubt and stops the rest. The full report is read last:
	// every acknowledgment a local report carries was then given before the
	// broker's view was taken, so a report landing during the pass never
	// reads as a loss.
	sort.Slice(live, func(a, b int) bool { return live[a].Metadata.Name < live[b].Metadata.Name })
	reports := make([]ActivityReport, len(live))
	ips := make([]string, len(live))
	readCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	limit := make(chan struct{}, j.replicaConcurrency())
	var wg sync.WaitGroup
	var failed atomic.Bool
	for i, r := range live {
		ip, e := netipString(r.Status.PodIP)
		if e != nil {
			return nil, false, false, errJanitorDoubt
		}
		ips[i] = ip
	}
	read := func(i int, path string) {
		report, e := j.replica(readCtx, ips[i], path)
		if e != nil || report.ReplicaStarted.IsZero() || report.RetentionSeconds < j.config.IdleSeconds {
			failed.Store(true)
			cancel()
			return
		}
		reports[i] = report
	}
	for i := 1; i < len(live); i++ {
		wg.Add(1)
		limit <- struct{}{}
		go func(i int) {
			defer func() { <-limit; wg.Done() }()
			read(i, ActivityLocalPath)
		}(i)
	}
	wg.Wait()
	if !failed.Load() {
		read(0, ActivityPath)
	}
	if failed.Load() {
		return nil, false, false, errJanitorDoubt
	}
	seen := map[string]time.Time{}
	young := false
	full := reports[0]
	durable := full.Durable
	// A durable report vouches only for as long as the broker's history for
	// its binding: a new, recreated or emptied history is young.
	historyYoung := durable && (full.HistoryStarted.IsZero() || full.HistoryStarted.After(cutoff))
	// The broker's history is whole only as far back as some live replica
	// can vouch: one whose reports have been acknowledged since before the
	// cutoff, and none of whose acknowledged writes the store has lost.
	var vouched time.Time
	lost := false
	var unaware []string
	for i, report := range reports {
		if report.ReplicaStarted.After(cutoff) {
			young = true
		}
		// Each replica's own stream: another replica's reports never
		// advance it, so a loss stays visible until this replica reports.
		if report.AckedSeq > 0 && report.AckedSeq > full.HistoryStreams[report.Replica] {
			lost = true
			if i > 0 {
				unaware = append(unaware, ips[i])
			}
		}
		if !report.FirstAcked.IsZero() && (vouched.IsZero() || report.FirstAcked.Before(vouched)) {
			vouched = report.FirstAcked
		}
		for _, a := range report.Sandboxes {
			if a.OwnerUID != "" && a.LastSeen.After(seen[a.OwnerUID]) {
				seen[a.OwnerUID] = a.LastSeen
			}
		}
	}
	switch {
	case historyYoung:
		return nil, false, false, janitorHold{"activity_history_young"}
	case durable && lost:
		// A replica saw writes acknowledged that the store no longer holds
		// (a restore): its next report restarts the history. A replica
		// asked only for its own activity has not read the broker's view,
		// and an idle one may never report: asking it for the full report
		// shows it the loss, and it reports once, holding rows or not.
		j.tellLost(ctx, unaware)
		return nil, false, false, janitorHold{"activity_history_lost"}
	case durable && (vouched.IsZero() || vouched.After(cutoff)) && young:
		// Every live replica started without an acknowledgment, or got its
		// first one within the idle window (a rollout, perhaps over a
		// restore), and some replica has not been up for the whole window:
		// nothing vouches for the window yet. Once every live replica has
		// been up a full window, their own memory covers it, so an idle
		// fleet that never reports is not held for ever.
		return nil, false, false, janitorHold{"activity_history_unverified"}
	}
	return seen, durable, young, nil
}

func netipString(s string) (string, error) {
	ip := net.ParseIP(s)
	if ip == nil || ip.IsUnspecified() {
		return "", errDenied
	}
	return ip.String(), nil
}

// tellLost asks each replica at ips for the full report, which reads the
// broker's view and so shows the replica its loss. Best effort: a replica
// not reached is asked again on the next pass, which holds meanwhile.
func (j *janitor) tellLost(ctx context.Context, ips []string) {
	limit := make(chan struct{}, j.replicaConcurrency())
	var wg sync.WaitGroup
	for _, ip := range ips {
		wg.Add(1)
		limit <- struct{}{}
		go func() {
			defer func() { <-limit; wg.Done() }()
			_, _ = j.replica(ctx, ip, ActivityPath)
		}()
	}
	wg.Wait()
}

func (j *janitor) replica(ctx context.Context, ip, path string) (ActivityReport, error) {
	var report ActivityReport
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, j.replicaURL(ip, path), nil)
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
