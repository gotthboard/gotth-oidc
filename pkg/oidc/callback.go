package oidc

import (
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxAuthorizationResponseBytes = 64 << 10

// AuthorizationError is a redacted OAuth authorization error. Description and
// URI are bounded display material; callers must not treat either as trusted
// HTML or an instruction.
type AuthorizationError struct {
	Code        string
	Description string
	URI         string
}

func (err *AuthorizationError) Error() string {
	if err == nil || err.Code == "" {
		return "OIDC authorization failed"
	}
	return "OIDC authorization failed: " + err.Code
}

// AuthorizationResponse is a parsed query, form-post, or JWT authorization
// response. Duplicate and mixed encodings are rejected by ParseCallback.
type AuthorizationResponse struct {
	Code        string
	State       string
	Issuer      string
	ResponseJWT string
	Error       *AuthorizationError
	Mode        ResponseMode
}

// ParseCallback parses a bounded OIDC authorization response from GET query or
// POST application/x-www-form-urlencoded input. It performs no token exchange.
func ParseCallback(request *http.Request) (AuthorizationResponse, error) {
	if request == nil || request.URL == nil {
		return AuthorizationResponse{}, fmt.Errorf("OIDC callback request is required")
	}
	var values url.Values
	switch request.Method {
	case http.MethodGet:
		if len(request.URL.RawQuery) > maxAuthorizationResponseBytes {
			return AuthorizationResponse{}, fmt.Errorf("OIDC callback query is oversized")
		}
		values = request.URL.Query()
		// Query is also the carrier for the plain `jwt` response mode.
	case http.MethodPost:
		if request.Body == nil || request.ContentLength > maxAuthorizationResponseBytes {
			return AuthorizationResponse{}, fmt.Errorf("OIDC callback form is missing or oversized")
		}
		mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/x-www-form-urlencoded" {
			return AuthorizationResponse{}, fmt.Errorf("OIDC callback content type is invalid")
		}
		request.Body = http.MaxBytesReader(nil, request.Body, maxAuthorizationResponseBytes)
		if err := request.ParseForm(); err != nil {
			return AuthorizationResponse{}, fmt.Errorf("OIDC callback form is invalid")
		}
		if request.URL.RawQuery != "" {
			return AuthorizationResponse{}, fmt.Errorf("OIDC callback mixes query and form parameters")
		}
		values = request.PostForm
	default:
		return AuthorizationResponse{}, fmt.Errorf("OIDC callback method is unsupported")
	}
	allowed := map[string]bool{"code": true, "state": true, "iss": true, "response": true, "error": true, "error_description": true, "error_uri": true}
	for name, entries := range values {
		if !allowed[name] || len(entries) != 1 {
			return AuthorizationResponse{}, fmt.Errorf("OIDC callback contains an unknown or duplicate parameter")
		}
	}
	bounded := func(name, value string, maximum int, token bool) error {
		if len(value) > maximum || !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 || (token && strings.IndexFunc(value, unicode.IsSpace) >= 0) {
			return fmt.Errorf("OIDC callback %s is invalid", name)
		}
		return nil
	}
	for name, value := range map[string]string{
		"code": values.Get("code"), "state": values.Get("state"), "issuer": values.Get("iss"),
		"response": values.Get("response"), "error": values.Get("error"),
	} {
		if err := bounded(name, value, maxAuthorizationResponseBytes, true); err != nil {
			return AuthorizationResponse{}, err
		}
	}
	if err := bounded("error description", values.Get("error_description"), 4096, false); err != nil {
		return AuthorizationResponse{}, err
	}
	if err := bounded("error URI", values.Get("error_uri"), 2048, false); err != nil {
		return AuthorizationResponse{}, err
	}
	mode := ResponseModeQuery
	if request.Method == http.MethodPost {
		mode = ResponseModeFormPost
	}
	response := AuthorizationResponse{Code: values.Get("code"), State: values.Get("state"), Issuer: values.Get("iss"), ResponseJWT: values.Get("response"), Mode: mode}
	if errorCode := values.Get("error"); errorCode != "" {
		if response.Code != "" || response.ResponseJWT != "" {
			return AuthorizationResponse{}, fmt.Errorf("OIDC callback combines success and error parameters")
		}
		response.Error = &AuthorizationError{Code: errorCode, Description: values.Get("error_description"), URI: values.Get("error_uri")}
		if response.State == "" {
			return AuthorizationResponse{}, fmt.Errorf("OIDC callback error response omits state")
		}
		return response, nil
	}
	if response.ResponseJWT != "" {
		if response.Code != "" || response.State != "" || response.Issuer != "" {
			return AuthorizationResponse{}, fmt.Errorf("OIDC callback combines JWT and direct response parameters")
		}
		return response, nil
	}
	if response.Code == "" || response.State == "" {
		return AuthorizationResponse{}, fmt.Errorf("OIDC callback success response is incomplete")
	}
	return response, nil
}

func validateResponseMode(expected ResponseMode, response AuthorizationResponse) error {
	actual := response.Mode
	if actual == "" {
		actual = ResponseModeQuery
	}
	switch expected {
	case ResponseModeQuery:
		if actual != ResponseModeQuery || response.ResponseJWT != "" {
			return fmt.Errorf("OIDC authorization response mode does not match the attempt")
		}
	case ResponseModeFormPost:
		if actual != ResponseModeFormPost || response.ResponseJWT != "" {
			return fmt.Errorf("OIDC authorization response mode does not match the attempt")
		}
	case ResponseModeJWT, ResponseModeQueryJWT:
		if actual != ResponseModeQuery || response.ResponseJWT == "" {
			return fmt.Errorf("OIDC authorization response mode does not match the attempt")
		}
	case ResponseModeFormJWT:
		if actual != ResponseModeFormPost || response.ResponseJWT == "" {
			return fmt.Errorf("OIDC authorization response mode does not match the attempt")
		}
	default:
		return fmt.Errorf("OIDC authorization response mode is invalid")
	}
	return nil
}
