package gcp

import (
	"strings"
	"testing"
)

func TestBuildImpersonationURL(t *testing.T) {
	t.Run("valid service account email is unchanged", func(t *testing.T) {
		email := "svc@my-project.iam.gserviceaccount.com"
		got := buildImpersonationURL(email)
		want := "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + email + ":generateIdToken"
		if got != want {
			t.Fatalf("unexpected URL:\n got: %s\nwant: %s", got, want)
		}
	})

	t.Run("path-injecting identifier is escaped", func(t *testing.T) {
		// A '/' would otherwise change the request path; PathEscape encodes it.
		got := buildImpersonationURL("foo/../../evil")
		if strings.Contains(got, "foo/../../evil") {
			t.Fatalf("path traversal not escaped: %s", got)
		}
		if !strings.HasSuffix(got, ":generateIdToken") {
			t.Fatalf("expected generateIdToken suffix: %s", got)
		}
	})
}
