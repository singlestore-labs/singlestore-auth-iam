package aws

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
			name:      "valid IAM role ARN",
			principal: "arn:aws:iam::123456789012:role/my-role",
			wantErr:   false,
		},
		{
			name:      "valid STS assumed-role ARN",
			principal: "arn:aws:sts::123456789012:assumed-role/my-role/session",
			wantErr:   false,
		},
		{
			name:      "empty principal",
			principal: "",
			wantErr:   true,
		},
		{
			name:      "non-ARN principal",
			principal: "not-an-arn",
			wantErr:   true,
		},
		{
			name:      "invalid account ID length",
			principal: "arn:aws:iam::12345:role/my-role",
			wantErr:   true,
		},
		{
			name:      "missing resource segment",
			principal: "arn:aws:iam::123456789012:",
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
