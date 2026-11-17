package sp

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/crewjam/saml"
	"github.com/roidmc/kexcore-saml/pkg/protocol"
	"github.com/roidmc/kexcore-saml/pkg/xmlsig"
)

// ServiceProvider is the SAML SP engine for one (tenant, identity provider)
// pair.
//
// It is safe for concurrent use. The host owns routing, tenancy and user
// storage; the engine owns the SAML wire format and its validation.
type ServiceProvider struct {
	cfg    Config
	engine *saml.ServiceProvider
}

// New validates the configuration and builds an SP engine.
func New(cfg Config) (*ServiceProvider, error) {
	if strings.TrimSpace(cfg.EntityID) == "" {
		return nil, ErrMissingEntityID
	}
	if strings.TrimSpace(cfg.ACSURL) == "" {
		return nil, ErrMissingACSURL
	}

	acsURL, err := parseAbsoluteURL(cfg.ACSURL)
	if err != nil {
		return nil, fmt.Errorf("%w: ACSURL: %v", ErrInvalidACSURL, err)
	}

	var metadataURL url.URL
	if cfg.MetadataURL != "" {
		parsed, err := parseAbsoluteURL(cfg.MetadataURL)
		if err != nil {
			return nil, fmt.Errorf("%w: MetadataURL: %v", ErrInvalidACSURL, err)
		}
		metadataURL = *parsed
	}

	var sloURL url.URL
	if cfg.SLOURL != "" {
		parsed, err := parseAbsoluteURL(cfg.SLOURL)
		if err != nil {
			return nil, fmt.Errorf("%w: SLOURL: %v", ErrInvalidACSURL, err)
		}
		sloURL = *parsed
	}

	idpMetadata, err := buildIdPMetadata(cfg.IdP)
	if err != nil {
		return nil, err
	}

	replayCache := cfg.ReplayCache
	if replayCache == nil {
		replayCache = NewMemoryReplayCache()
	}

	engine := &saml.ServiceProvider{
		EntityID:              cfg.EntityID,
		AcsURL:                *acsURL,
		SloURL:                sloURL,
		MetadataURL:           metadataURL,
		IDPMetadata:           idpMetadata,
		AuthnNameIDFormat:     saml.NameIDFormat(cfg.NameIDFormat),
		AllowIDPInitiated:     cfg.AllowIDPInitiated,
		Key:                   cfg.Key,
		Certificate:           cfg.Certificate,
		EncryptionKey:         cfg.EncryptionKey,
		EncryptionCertificate: cfg.EncryptionCertificate,
		DecryptionKeys:        cfg.DecryptionKeys,
		ReplayCache:           replayCache,
		Clock:                 cfg.Clock,
		MetadataValidDuration: cfg.MetadataValidDuration,

		// This release accepts only the HTTP-POST binding at the ACS. The
		// HTTP-Artifact binding would require resolving artifacts back to
		// the IdP, which the host does not provide yet.
		AssertionConsumerServiceBindings: []string{saml.HTTPPostBinding},

		// SHA-1 is refused unless explicitly allowed by the operator.
		RejectSHA1Signatures: !cfg.AllowSHA1,
	}

	return &ServiceProvider{cfg: cfg, engine: engine}, nil
}

// EntityID returns the SP entity identifier.
func (p *ServiceProvider) EntityID() string { return p.engine.EntityID }

// IDPEntityID returns the identity provider's entity identifier.
func (p *ServiceProvider) IDPEntityID() string {
	if p.engine.IDPMetadata == nil {
		return ""
	}
	return p.engine.IDPMetadata.EntityID
}

// SSOURL returns the identity provider's SingleSignOnService location the
// engine will send AuthnRequests to.
func (p *ServiceProvider) SSOURL() string {
	return p.engine.GetSSOBindingLocation(saml.HTTPRedirectBinding)
}

// Metadata returns the SP metadata document, ready to be served at the
// configured MetadataURL and handed to the identity provider.
func (p *ServiceProvider) Metadata() ([]byte, error) {
	descriptor := p.engine.Metadata()
	if descriptor == nil {
		return nil, fmt.Errorf("kexcore-saml: failed to build SP metadata")
	}
	body, err := xml.Marshal(descriptor)
	if err != nil {
		return nil, fmt.Errorf("kexcore-saml: marshal SP metadata: %w", err)
	}
	return append([]byte(xml.Header), body...), nil
}

// AuthnRequest starts a SP-initiated login.
//
// It returns the redirect URL to send the browser to and the request ID. The
// ID must be persisted by the host (together with the tenant, provider and
// return URL) and passed back to ParseResponse as a possible request ID, so
// that an unsolicited response cannot be accepted in its place.
func (p *ServiceProvider) AuthnRequest(relayState string) (redirectURL string, requestID string, err error) {
	location := p.engine.GetSSOBindingLocation(saml.HTTPRedirectBinding)
	if location == "" {
		location = p.engine.GetSSOBindingLocation(saml.HTTPPostBinding)
	}
	if location == "" {
		return "", "", ErrNoSSOEndpoint
	}

	request, err := p.engine.MakeAuthenticationRequest(location, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return "", "", fmt.Errorf("kexcore-saml: build AuthnRequest: %w", err)
	}

	redirect, err := request.Redirect(relayState, p.engine)
	if err != nil {
		return "", "", fmt.Errorf("kexcore-saml: redirect AuthnRequest: %w", err)
	}
	return redirect.String(), request.ID, nil
}

// ParseResponse validates a POSTed SAML response and returns the identity it
// asserts.
//
// possibleRequestIDs are the IDs of AuthnRequests this SP is still waiting
// for. Pass nil only when AllowIDPInitiated is enabled.
func (p *ServiceProvider) ParseResponse(r *http.Request, possibleRequestIDs []string) (*protocol.Identity, error) {
	if r == nil {
		return nil, fmt.Errorf("kexcore-saml: nil request")
	}
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("kexcore-saml: parse form: %w", err)
	}

	// Harden the document before the engine parses it: SAML is XML, and XML
	// parser differentials are the classic way past signature checks. The
	// engine would still reject a forged signature, but rejecting a document
	// that does not survive a round trip removes a whole class of ambiguity.
	if encoded := r.PostForm.Get("SAMLResponse"); encoded != "" {
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("kexcore-saml: decode SAMLResponse: %w", err)
		}
		if err := xmlsig.Validate(decoded); err != nil {
			return nil, err
		}
	}

	assertion, err := p.engine.ParseResponse(r, possibleRequestIDs)
	if err != nil {
		return nil, err
	}
	return identityFromAssertion(assertion), nil
}

// ParseResponseXML validates a decoded SAML response without an HTTP request.
// It exists for tests, replay tooling and hosts that terminate the POST
// elsewhere. currentURL defaults to the configured ACS URL.
func (p *ServiceProvider) ParseResponseXML(raw []byte, possibleRequestIDs []string, currentURL *url.URL) (*protocol.Identity, error) {
	if err := xmlsig.Validate(raw); err != nil {
		return nil, err
	}

	acsURL := p.engine.AcsURL
	if currentURL != nil {
		acsURL = *currentURL
	}

	assertion, err := p.engine.ParseXMLResponse(raw, possibleRequestIDs, acsURL)
	if err != nil {
		return nil, err
	}
	return identityFromAssertion(assertion), nil
}

func identityFromAssertion(assertion *saml.Assertion) *protocol.Identity {
	identity := &protocol.Identity{Attributes: make(map[string][]string)}
	if assertion == nil {
		return identity
	}

	identity.Issuer = assertion.Issuer.Value

	if assertion.Subject != nil {
		if assertion.Subject.NameID != nil {
			identity.NameID = assertion.Subject.NameID.Value
			identity.NameIDFormat = assertion.Subject.NameID.Format
		}
		for _, confirmation := range assertion.Subject.SubjectConfirmations {
			if confirmation.SubjectConfirmationData == nil {
				continue
			}
			if !confirmation.SubjectConfirmationData.NotOnOrAfter.IsZero() {
				identity.NotOnOrAfter = confirmation.SubjectConfirmationData.NotOnOrAfter
				break
			}
		}
	}

	if assertion.Conditions != nil && !assertion.Conditions.NotOnOrAfter.IsZero() {
		identity.NotOnOrAfter = assertion.Conditions.NotOnOrAfter
	}

	if len(assertion.AuthnStatements) > 0 {
		identity.SessionIndex = assertion.AuthnStatements[0].SessionIndex
	}

	for _, statement := range assertion.AttributeStatements {
		for _, attribute := range statement.Attributes {
			for _, value := range attribute.Values {
				text := value.Value
				if text == "" && value.NameID != nil {
					text = value.NameID.Value
				}
				if text == "" {
					continue
				}
				identity.Attributes[attribute.Name] = append(identity.Attributes[attribute.Name], text)
				if canonical := protocol.CanonicalAttribute(attribute.Name); canonical != attribute.Name {
					identity.Attributes[canonical] = append(identity.Attributes[canonical], text)
				}
			}
		}
	}

	return identity
}

func parseAbsoluteURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if !parsed.IsAbs() || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("not an absolute http(s) URL")
	}
	return parsed, nil
}
