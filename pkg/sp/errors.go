package sp

import "github.com/crewjam/saml"

// Sentinel errors returned by the service provider engine.
var (
	// ErrMissingEntityID means Config.EntityID was empty.
	ErrMissingEntityID = errString("kexcore-saml: EntityID is required")
	// ErrMissingACSURL means Config.ACSURL was empty.
	ErrMissingACSURL = errString("kexcore-saml: ACSURL is required")
	// ErrInvalidACSURL means ACSURL, SLOURL or MetadataURL was not an
	// absolute http(s) URL.
	ErrInvalidACSURL = errString("kexcore-saml: URL must be absolute and use http or https")
	// ErrMissingIdP means neither metadata nor SSOURL and certificates were
	// supplied.
	ErrMissingIdP = errString("kexcore-saml: IdP metadata or SSOURL with certificates is required")
	// ErrNoSSOEndpoint means the identity provider publishes no usable
	// SingleSignOnService.
	ErrNoSSOEndpoint = errString("kexcore-saml: identity provider publishes no SingleSignOnService")
	// ErrNoSigningCertificate means no IdP signing certificate could be
	// resolved, so no assertion can be trusted.
	ErrNoSigningCertificate = errString("kexcore-saml: identity provider publishes no signing certificate")
	// ErrReplay is returned when an assertion ID has already been consumed.
	// It is the engine's replay sentinel.
	ErrReplay = saml.ErrAssertionReplayed
)

// errString is a tiny error type that keeps the sentinels comparable with
// errors.Is while avoiding a dependency on the host's error package.
type errString string

func (e errString) Error() string { return string(e) }
