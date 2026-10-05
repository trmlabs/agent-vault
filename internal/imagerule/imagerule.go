// Package imagerule decides which pulled images an agent Pod may run: an exact
// digest, or a TRM sandbox repository prefix. It matches what the node pulled
// (a container status's imageID), never what the Pod spec asked for.
package imagerule

import (
	"regexp"
	"strings"
)

var (
	digest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// A whole repository, or a repository and one tenant segment, in the
	// agent-sandbox project's Artifact Registry only.
	prefix = regexp.MustCompile(`^us-central1-docker\.pkg\.dev/trm-agent-sandbox/[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?/([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?/)?$`)
	// An image reference by the OCI distribution grammar: an optional
	// registry host (and port), then path components of lowercase letters
	// and digits joined by single separators, so ".", ".." and empty
	// components never parse.
	domainPart = `[a-z0-9]([a-z0-9-]*[a-z0-9])?`
	pathPart   = `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*`
	ref        = regexp.MustCompile(`^(` + domainPart + `(\.` + domainPart + `)*(:[0-9]{1,5})?/)?` + pathPart + `(/` + pathPart + `)*@sha256:[0-9a-f]{64}$`)
)

// ValidDigest reports whether d is sha256: and 64 lowercase hex characters.
func ValidDigest(d string) bool { return digest.MatchString(d) }

// ValidPrefix reports whether p is a whole agent-sandbox repository or one
// tenant path in it, ending in "/".
func ValidPrefix(p string) bool { return prefix.MatchString(p) }

// Overlap reports whether one prefix contains the other (or they are equal):
// two profiles may never claim the same images.
func Overlap(a, b string) bool { return strings.HasPrefix(a, b) || strings.HasPrefix(b, a) }

// Split returns a pulled image reference's repository and digest. A bare
// digest (a locally loaded image) has no repository.
func Split(imageID string) (repository, d string, ok bool) {
	imageID = strings.TrimPrefix(imageID, "docker-pullable://")
	if digest.MatchString(imageID) {
		return "", imageID, true
	}
	if len(imageID) > 600 || !ref.MatchString(imageID) {
		return "", "", false
	}
	i := strings.LastIndexByte(imageID, '@')
	return imageID[:i], imageID[i+1:], true
}

// Allowed reports whether a pulled image may run: its digest is listed, or
// its repository lies under prefix (when prefix is set).
func Allowed(imageID, prefix string, digests []string) bool {
	repository, d, ok := Split(imageID)
	if !ok {
		return false
	}
	for _, allowed := range digests {
		if d == allowed {
			return true
		}
	}
	return prefix != "" && repository != "" && strings.HasPrefix(repository+"/", prefix) && len(repository)+1 > len(prefix)
}
