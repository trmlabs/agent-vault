package cmd

import "testing"

func TestCleanupObserverPortRequiresBothSettings(t *testing.T) {
	for _, tc := range []struct {
		path, value string
		valid       bool
	}{{"", "", true}, {"policy.json", "14324", true}, {"policy.json", "", false}, {"", "14324", false}, {"policy.json", "0", false}, {"policy.json", "65536", false}, {"policy.json", "+14324", false}, {"policy.json", "014324", false}, {"policy.json", "0.0.0.0:14324", false}} {
		_, err := cleanupObserverPort(tc.path, tc.value)
		if (err == nil) != tc.valid {
			t.Fatalf("%q %q: %v", tc.path, tc.value, err)
		}
	}
}
