package azure

import (
	"strings"
	"testing"
)

func TestBuildIMDSTokenURL(t *testing.T) {
	t.Run("system-assigned has no client_id", func(t *testing.T) {
		got := buildIMDSTokenURL(azureResourceServer, "")
		if strings.Contains(got, "client_id=") {
			t.Fatalf("did not expect client_id in URL: %s", got)
		}
		if !strings.Contains(got, "resource="+azureResourceServer) {
			t.Fatalf("expected resource in URL: %s", got)
		}
	})

	t.Run("user-assigned appends escaped client_id", func(t *testing.T) {
		got := buildIMDSTokenURL(azureResourceServer, "11111111-2222-3333-4444-555555555555")
		if !strings.Contains(got, "&client_id=11111111-2222-3333-4444-555555555555") {
			t.Fatalf("expected client_id query param: %s", got)
		}
	})

	t.Run("malformed client_id cannot inject query params", func(t *testing.T) {
		// A value with '&' and '=' must be escaped so it stays a single
		// client_id value rather than adding new IMDS query parameters.
		got := buildIMDSTokenURL(azureResourceServer, "evil&api-version=2099-99-99&resource=https://attacker")
		if strings.Contains(got, "&api-version=2099-99-99") {
			t.Fatalf("injection not prevented: %s", got)
		}
		if !strings.Contains(got, "client_id=evil%26api-version%3D2099-99-99%26resource%3Dhttps%3A%2F%2Fattacker") {
			t.Fatalf("client_id was not escaped as expected: %s", got)
		}
	})
}
