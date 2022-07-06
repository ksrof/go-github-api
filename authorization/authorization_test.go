package authorization_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ksrof/go-github-api/authorization"
)

// fixtures
const mockToken string = "ghp_a2gcJYu1lxkgVDduggjh6x1plhbJcQxDz9W0"

func TestBasic(t *testing.T) {
	tests := []struct {
		name    string
		opts    []authorization.Option
		want    string
		wantErr error
	}{
		{
			name: "test with valid token",
			opts: []authorization.Option{
				authorization.WithToken(mockToken),
			},
			want: mockToken,
		},
		{
			name: "test with invalid token",
			opts: []authorization.Option{
				authorization.WithToken("abc123"),
			},
			wantErr: authorization.ErrInvalidToken,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			auth, err := authorization.New(
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
