// Package idp is the reserved home of the outbound SAML identity provider.
//
// This release ships the Service Provider side only: KexCore lets users sign
// in through a tenant's identity provider, but does not itself issue SAML
// assertions to downstream applications. The interfaces below fix the seam so
// that adding the outbound role later does not change the SP API, the module
// layout, or the host-facing provider contract.
//
// Until an implementation exists, every entry point returns ErrNotImplemented.
package idp

import (
	"context"
	"errors"
	"time"

	"github.com/roidmc/kexcore-saml/pkg/protocol"
)

// ErrNotImplemented is returned by every outbound IdP entry point in this
// release.
var ErrNotImplemented = errors.New("kexcore-saml: outbound identity provider is not implemented")

// IssueRequest describes one assertion to issue to a downstream service
// provider.
type IssueRequest struct {
	// EntityID is the issuing KexCore entity identifier.
	EntityID string
	// Audience is the downstream service provider's entity ID.
	Audience string
	// ACSURL is where the response will be delivered.
	ACSURL string
	// NameID identifies the subject in the assertion.
	NameID       string
	NameIDFormat protocol.NameIDFormat
	// SessionIndex ties the assertion to the host's own session.
	SessionIndex string
	// Attributes is copied into the assertion as-is.
	Attributes map[string][]string
	// NotOnOrAfter bounds the assertion's validity. Zero means the
	// implementation's default.
	NotOnOrAfter time.Time
}

// IdentityProvider is the outbound role. It is intentionally unimplemented in
// this release.
type IdentityProvider interface {
	// Metadata returns the IdP's SAML metadata document.
	Metadata() ([]byte, error)
	// Issue returns a signed SAML Response for the request.
	Issue(ctx context.Context, req IssueRequest) ([]byte, error)
}
