package authentication_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ksrof/go-github-api/authentication"
)

// fixtures
const mockToken string = "ghp_a2gcJYu1lxkgVDduggjh6x1plhbJcQxDz9W0"

func TestBasic(t *testing.T) {
	tests := []struct {
		name    string
		opts    []authentication.Option
		want    string
		wantErr error
	}{
		{
			name: "test with valid token",
			opts: []authentication.Option{
				authentication.WithToken(mockToken),
			},
			want: mockToken,
		},
		{
			name: "test with invalid token",
			opts: []authentication.Option{
				authentication.WithToken("abc123"),
			},
			wantErr: authentication.ErrInvalidToken,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			auth, err := authentication.New(
				tc.opts...,
			)
			if err != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Logf("want: %v, got: %v\n", tc.wantErr, err)
					return
				}
			} else {
				token := auth.Basic()
				if !strings.Contains(tc.want, token) {
					t.Logf("want: %s, got: %s\n", tc.want, token)
					return
				}
			}

		})
	}
}
