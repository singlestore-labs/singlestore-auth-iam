package gcp

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/singlestore-labs/singlestore-auth-iam/go/internal/gates"
)

func TestValidatePrincipal(t *testing.T) {
	if !gates.S2IAMValidatePrincipal.Enabled() {
		t.Skip("S2IAMValidatePrincipal gate is disabled")
	}

	tests := []struct {
		name      string
		principal string
		wantErr   bool
	}{
		{
			name:      "iam service account email",
			principal: "my-sa@my-project.iam.gserviceaccount.com",
			wantErr:   false,
		},
		{
			name:      "developer service account email",
			principal: "123456789012-compute@developer.gserviceaccount.com",
			wantErr:   false,
		},
		{
			name:      "numeric principal",
			principal: "123456789012",
			wantErr:   false,
		},
		{
			name:      "short numeric principal",
			principal: "123456789",
			wantErr:   true,
		},
		{
			name:      "empty principal",
			principal: "",
			wantErr:   true,
		},
		{
			name:      "invalid email domain",
			principal: "user@example.com",
			wantErr:   true,
		},
		{
			name:      "invalid principal format",
			principal: "not-valid",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePrincipal(tt.principal)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
