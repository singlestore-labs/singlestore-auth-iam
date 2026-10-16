package gcp

import (
	"strings"
	"testing"
)

func TestBuildImpersonationURL(t *testing.T) {
	email := "service-account@project-id.iam.gserviceaccount.com"
	got := buildImpersonationURL(email)
	want := "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + email + ":generateIdToken"
	if got != want {
		t.Fatalf("impersonation URL = %s, want %s", got, want)
	}

	// A slash must stay inside the service-account segment. ':' is left alone,
	// matching url.PathEscape.
	injected := buildImpersonationURL("evil/other:generateAccessToken")
	if strings.Contains(injected, "/evil/other") {
		t.Fatalf("email must not add a path segment, got %s", injected)
	}
	if !strings.Contains(injected, "evil%2Fother:generateAccessToken") {
		t.Fatalf("email should be path-escaped, got %s", injected)
	}
}
