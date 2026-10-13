package azure

import (
	"strings"
	"testing"
)

func TestBuildIMDSTokenURL(t *testing.T) {
	plain := buildIMDSTokenURL("https://management.azure.com/", "")
	if strings.Contains(plain, "client_id=") {
		t.Fatalf("system-assigned URL should omit client_id, got %s", plain)
	}
	if !strings.Contains(plain, "resource=https://management.azure.com/") {
		t.Fatalf("default resource should stay unescaped, got %s", plain)
	}

	id := "12345678-1234-1234-1234-123456789012"
	withID := buildIMDSTokenURL("https://management.azure.com/", id)
	if !strings.HasSuffix(withID, "&client_id="+id) {
		t.Fatalf("UUID client id should be appended unchanged, got %s", withID)
	}

	// A value that looks like extra query parameters must be escaped into one value.
	injected := buildIMDSTokenURL("https://management.azure.com/", "abc&resource=https://evil.example/")
	if strings.Contains(injected, "&resource=https://evil.example/") {
		t.Fatalf("client_id must not inject query parameters, got %s", injected)
	}
	if !strings.Contains(injected, "client_id=abc%26resource%3Dhttps%3A%2F%2Fevil.example%2F") {
		t.Fatalf("client_id should be query-escaped, got %s", injected)
	}
}
