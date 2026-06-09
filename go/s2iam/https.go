package s2iam

import (
	"net/url"

	"github.com/memsql/errors"
)

func validateAuthServerURL(rawURL string, allowHTTP bool) (*url.URL, error) {
	uri, err := url.Parse(rawURL)
	if err != nil {
		return nil, errors.Errorf("invalid server URL: %w", err)
	}
	switch uri.Scheme {
	case "https":
		return uri, nil
	case "http":
		if allowHTTP {
			return uri, nil
		}
		return nil, errors.New("authentication server URL must use HTTPS; use WithAllowHTTP() for testing")
	default:
		return nil, errors.Errorf("authentication server URL must use HTTPS (got scheme %q)", uri.Scheme)
	}
}
