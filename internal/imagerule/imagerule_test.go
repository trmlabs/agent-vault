package imagerule

import "testing"

const (
	orion     = "us-central1-docker.pkg.dev/trm-agent-sandbox/agent-sandbox-images-staging/orion/"
	developer = "us-central1-docker.pkg.dev/trm-agent-sandbox/agent-sandbox-developers-staging/"
	d1        = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	d2        = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

func TestPrefixShape(t *testing.T) {
	for p, ok := range map[string]bool{
		orion: true, developer: true,
		"us-central1-docker.pkg.dev/trm-agent-sandbox/":                                false, // the whole project
		"us-central1-docker.pkg.dev/other-project/agent-sandbox-images-staging/orion/": false,
		"us-central1-docker.pkg.dev/trm-agent-sandbox/repo/orion/team/":                false, // deeper than one tenant
		"us-central1-docker.pkg.dev/trm-agent-sandbox/repo/orion":                      false, // no trailing slash
		"europe-docker.pkg.dev/trm-agent-sandbox/repo/":                                false,
		"us-central1-docker.pkg.dev/trm-agent-sandbox/Repo/":                           false,
	} {
		if ValidPrefix(p) != ok {
			t.Errorf("%s: %v", p, !ok)
		}
	}
	if !Overlap(orion, "us-central1-docker.pkg.dev/trm-agent-sandbox/agent-sandbox-images-staging/") || Overlap(orion, developer) || !Overlap(orion, orion) {
		t.Error("overlap")
	}
}

func TestAllowedMatchesThePulledImage(t *testing.T) {
	for id, ok := range map[string]bool{
		"us-central1-docker.pkg.dev/trm-agent-sandbox/agent-sandbox-images-staging/orion/agent@" + d2:     true,
		"us-central1-docker.pkg.dev/trm-agent-sandbox/agent-sandbox-images-staging/orion/a/b@" + d2:       true,
		"us-central1-docker.pkg.dev/trm-agent-sandbox/agent-sandbox-images-staging/gatehouse/proxy@" + d2: false, // the proxy image is never an agent image
		"us-central1-docker.pkg.dev/trm-agent-sandbox/agent-sandbox-images-staging/orionx/agent@" + d2:    false,
		"us-central1-docker.pkg.dev/trm-agent-sandbox/agent-sandbox-images-staging/orion@" + d2:           false, // the prefix itself is no image
		"docker.io/library/busybox@" + d1: true, // an exact platform digest
		d1:                                true,
		"docker.io/library/busybox@" + d2: false,
		"us-central1-docker.pkg.dev/trm-agent-sandbox/agent-sandbox-images-staging/orion/agent:latest": false, // a tag, not a pull
		"": false,
	} {
		if Allowed(id, orion, []string{d1}) != ok {
			t.Errorf("%s: %v", id, !ok)
		}
	}
	if Allowed("us-central1-docker.pkg.dev/trm-agent-sandbox/agent-sandbox-developers-staging/x@"+d2, "", []string{d1}) {
		t.Error("no prefix still matched a repository")
	}
}
