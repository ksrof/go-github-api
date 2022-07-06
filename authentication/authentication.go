package authentication

import (
	"context"
	"errors"
	"regexp"
)

var (
	ErrInvalidClientID    error = errors.New("invalid <client_id>")
	ErrInvalidRedirectURI error = errors.New("invalid <redirect_uri>")
	ErrInvalidLogin       error = errors.New("invalid <login>")
	ErrInvalidScope       error = errors.New("invalid <scope>")
	ErrInvalidState       error = errors.New("invalid <state>")
	ErrInvalidAllowSignup error = errors.New("invalid <allow_signup>")
	ErrInvalidToken       error = errors.New("invalid <token>")
)

// Authentication is the interface that wraps the Github API
// authentication methods.
type Authentication interface {
	// Basic returns the Github OAuth token to be used in
	// the Authorization request header.
	//
	// Basic must return a non-empty string.
	Basic() string

	// WebApplication starts a web application flow to authorize
	// users in standard OAuth apps that run in the browser.
	//
	// WebApplication must return a non-empty string if the request succeeds.
	//
	// WebApplication must return a non-nil error if the request fails.
	WebApplication(ctx context.Context) (string, error)

	// Device starts a device flow to authorize users in headless
	// apps such as a CLI tool or Git credential manager.
	//
	// Device must return a non-empty string if the request succeeds.
	//
	// Device must return a non-nil error if the request fails.
	Device(ctx context.Context) (string, error)
}

type Option func(a *authentication) error

type authentication struct {
	client_id    string
	redirect_uri string
	login        string
	scope        string
	state        string
	allow_signup string
	token        string
}

func New(opts ...Option) (Authentication, error) {
	a := &authentication{}

	for _, opt := range opts {
		err := opt(a)
		if err != nil {
			return nil, err
		}
	}

	return a, nil
}

func WithClientID(client_id string) Option {
	return func(a *authentication) error {
		a.client_id = client_id
		return nil
	}
}

func WithRedirectURI(redirect_uri string) Option {
	return func(a *authentication) error {
		a.redirect_uri = redirect_uri
		return nil
	}
}

func WithLogin(login string) Option {
	return func(a *authentication) error {
		a.login = login
		return nil
	}
}

func WithScope(scope string) Option {
	return func(a *authentication) error {
		a.scope = scope
		return nil
	}
}

func WithState(state string) Option {
	return func(a *authentication) error {
		a.state = state
		return nil
	}
}

func WithAllowSignup(allow_signup string) Option {
	return func(a *authentication) error {
		a.allow_signup = allow_signup
		return nil
	}
}

func WithToken(token string) Option {
	return func(a *authentication) error {
		err := validateToken(token)
		if err != nil {
			return err
		}

		a.token = token
		return nil
	}
}

func (a *authentication) Basic() string {
	return a.token
}

func (a *authentication) WebApplication(ctx context.Context) (string, error) {
	return a.token, nil
}

func (a *authentication) Device(ctx context.Context) (string, error) {
	return a.token, nil
}

func validateToken(token string) error {
	pattern := regexp.MustCompile("[A-Za-z0-9_]{40}")
	ok := pattern.MatchString(token)
	if !ok {
		return ErrInvalidToken
	}

	return nil
}
