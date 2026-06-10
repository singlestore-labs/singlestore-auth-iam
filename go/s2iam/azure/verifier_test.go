package azure

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
			name:      "valid lowercase UUID",
			principal: "550e8400-e29b-41d4-a716-446655440000",
			wantErr:   false,
		},
		{
			name:      "valid uppercase UUID",
			principal: "550E8400-E29B-41D4-A716-446655440000",
			wantErr:   false,
		},
		{
			name:      "empty principal",
			principal: "",
			wantErr:   true,
		},
		{
			name:      "non-UUID principal",
			principal: "not-a-uuid",
			wantErr:   true,
		},
		{
			name:      "partial UUID",
			principal: "550e8400-e29b-41d4-a716",
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
