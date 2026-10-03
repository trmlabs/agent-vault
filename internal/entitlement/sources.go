package entitlement

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"time"
)

// FileSource reads a JSON directory on every lookup. It stands in for Entra
// in tests and fixtures: {"subjects": {"<sso subject>": {"objectID": "...",
// "enabled": true, "groups": ["<group id>", ...]}}}.
type FileSource struct{ Path string }

func (f FileSource) Lookup(_ context.Context, subject string, groups []string) (Person, error) {
	data, err := os.ReadFile(f.Path)
	if err != nil || len(data) > 1<<20 {
		return Person{}, errors.New("entitlement directory unavailable")
	}
	var dir struct {
		Subjects map[string]struct {
			ObjectID string   `json:"objectID"`
			Enabled  bool     `json:"enabled"`
			Groups   []string `json:"groups"`
		} `json:"subjects"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&dir) != nil {
		return Person{}, errors.New("invalid entitlement directory")
	}
	user, ok := dir.Subjects[subject]
	if !ok {
		return Person{}, errors.New("subject not in directory")
	}
	return Person{ObjectID: user.ObjectID, Enabled: user.Enabled, MemberOf: intersect(groups, user.Groups)}, nil
}

func intersect(asked, have []string) []string {
	set := map[string]bool{}
	for _, h := range have {
		set[h] = true
	}
	var out []string
	for _, a := range asked {
		if set[a] {
			out = append(out, a)
		}
	}
	return out
}

var objectID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// GraphSource asks Microsoft Graph with an application token: the user by the
// SSO subject, then POST /users/{id}/checkMemberGroups for the asked groups
// (GroupMember.Read.All and User.Read.All, application). It is off unless
// configured; creating its app registration is a Security decision.
type GraphSource struct {
	Endpoint string // https://graph.microsoft.com/v1.0
	Token    func(context.Context) (string, error)
	Client   *http.Client
	// SubjectIsObjectID: the SSO subject is the Entra object ID. Otherwise it
	// is looked up as a user principal name. Email alone is never used.
	SubjectIsObjectID bool
}

func (g GraphSource) Lookup(ctx context.Context, subject string, groups []string) (Person, error) {
	for _, group := range groups {
		if !objectID.MatchString(group) {
			return Person{}, errors.New("entitlement groups must be Entra object IDs")
		}
	}
	var user struct {
		ID      string `json:"id"`
		Enabled *bool  `json:"accountEnabled"`
	}
	path := "/users/" + url.PathEscape(subject) + "?$select=id,accountEnabled"
	if g.SubjectIsObjectID && !objectID.MatchString(subject) {
		return Person{}, errors.New("subject is not an object ID")
	}
	if err := g.call(ctx, http.MethodGet, path, nil, &user); err != nil || user.Enabled == nil || !objectID.MatchString(user.ID) {
		return Person{}, errors.New("directory user lookup failed")
	}
	var member struct {
		Value []string `json:"value"`
	}
	body, _ := json.Marshal(map[string][]string{"groupIds": groups})
	if err := g.call(ctx, http.MethodPost, "/users/"+user.ID+"/checkMemberGroups", body, &member); err != nil {
		return Person{}, errors.New("directory membership lookup failed")
	}
	return Person{ObjectID: user.ID, Enabled: *user.Enabled, MemberOf: intersect(groups, member.Value)}, nil
}

func (g GraphSource) call(ctx context.Context, method, path string, body []byte, out any) error {
	token, err := g.Token(ctx)
	if err != nil || token == "" {
		return errors.New("directory token unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, g.Endpoint+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := g.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("directory returned %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}
