package sp

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/roidmc/kexcore-saml/pkg/protocol"
	"github.com/roidmc/kexcore-saml/pkg/xmlsig"
)

const defaultMaxMetadataBytes int64 = 1 << 20

// FetchOptions configures FetchMetadata.
type FetchOptions struct {
	// HTTPClient is used for the request. A client with a 10 second timeout
	// is used when nil.
	HTTPClient *http.Client
	// MaxBytes caps the document size. Defaults to 1 MiB.
	MaxBytes int64
	// AllowInsecureHTTP permits plain http URLs. Off by default so that
	// metadata is fetched over TLS.
	AllowInsecureHTTP bool
}

// FetchMetadata downloads and round-trip validates an identity provider
// metadata document.
//
// Fetching is deliberately separate from New: the host decides when metadata
// is refreshed, how it is cached and what trust anchors it accepts. New only
// consumes bytes.
func FetchMetadata(ctx context.Context, rawURL string, opts FetchOptions) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidACSURL, err)
	}
	if parsed.Scheme != "https" && !(opts.AllowInsecureHTTP && parsed.Scheme == "http") {
		return nil, fmt.Errorf("%w: metadata URL must use https", ErrInvalidACSURL)
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/samlmetadata+xml, application/xml, text/xml")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kexcore-saml: fetch metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kexcore-saml: fetch metadata: unexpected status %d", resp.StatusCode)
	}

	limit := opts.MaxBytes
	if limit <= 0 {
		limit = defaultMaxMetadataBytes
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("kexcore-saml: read metadata: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("kexcore-saml: metadata exceeds %d bytes", limit)
	}
	if err := xmlsig.Validate(body); err != nil {
		return nil, err
	}
	return body, nil
}

// buildIdPMetadata resolves the configured identity provider into the
// normalized EntityDescriptor the engine consumes. Only the SSO/SLO endpoints
// and the signing certificates are carried over; everything else in the
// source metadata is irrelevant to assertion validation.
func buildIdPMetadata(cfg IdPConfig) (*saml.EntityDescriptor, error) {
	if len(cfg.MetadataXML) == 0 && cfg.SSOURL == "" {
		return nil, ErrMissingIdP
	}

	var (
		entityID string
		ssoURL   string
		sloURL   string
		certs    []*x509.Certificate
	)

	if len(cfg.MetadataXML) > 0 {
		if err := xmlsig.Validate(cfg.MetadataXML); err != nil {
			return nil, err
		}
		md, err := selectEntity(cfg.MetadataXML, cfg.EntityID)
		if err != nil {
			return nil, err
		}
		if len(md.IDPSSODescriptors) == 0 {
			return nil, fmt.Errorf("kexcore-saml: metadata %q has no IDPSSODescriptor", md.EntityID)
		}
		if cfg.EntityID != "" && md.EntityID != "" && md.EntityID != cfg.EntityID {
			return nil, fmt.Errorf("kexcore-saml: metadata entityID %q does not match configured %q", md.EntityID, cfg.EntityID)
		}
		desc := &md.IDPSSODescriptors[0]
		entityID = md.EntityID
		ssoURL = ssoLocation(desc)
		sloURL = sloLocation(desc)
		certs, err = certificatesFromDescriptor(desc)
		if err != nil {
			return nil, err
		}
	}

	if cfg.SSOURL != "" {
		ssoURL = cfg.SSOURL
	}
	if cfg.SLOURL != "" {
		sloURL = cfg.SLOURL
	}
	if ssoURL == "" {
		return nil, ErrNoSSOEndpoint
	}
	if entityID == "" {
		entityID = cfg.EntityID
	}

	if len(cfg.Certificates) > 0 {
		parsed, err := parseCertificates(cfg.Certificates)
		if err != nil {
			return nil, err
		}
		certs = append(certs, parsed...)
	}
	certs = dedupeCertificates(certs)
	if len(certs) == 0 {
		return nil, ErrNoSigningCertificate
	}

	return normalizedDescriptor(entityID, ssoURL, sloURL, certs), nil
}

// selectEntity extracts the relevant EntityDescriptor from either an
// EntityDescriptor or an EntitiesDescriptor document.
func selectEntity(data []byte, want string) (*saml.EntityDescriptor, error) {
	var root struct {
		XMLName xml.Name
	}
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("kexcore-saml: parse metadata: %w", err)
	}

	switch root.XMLName.Local {
	case "EntityDescriptor":
		var md saml.EntityDescriptor
		if err := xml.Unmarshal(data, &md); err != nil {
			return nil, fmt.Errorf("kexcore-saml: parse metadata: %w", err)
		}
		if len(md.IDPSSODescriptors) == 0 {
			return nil, fmt.Errorf("kexcore-saml: metadata %q has no IDPSSODescriptor", md.EntityID)
		}
		return &md, nil

	case "EntitiesDescriptor":
		var list struct {
			EntityDescriptors []saml.EntityDescriptor `xml:"EntityDescriptor"`
		}
		if err := xml.Unmarshal(data, &list); err != nil {
			return nil, fmt.Errorf("kexcore-saml: parse metadata: %w", err)
		}
		for i := range list.EntityDescriptors {
			md := &list.EntityDescriptors[i]
			if len(md.IDPSSODescriptors) == 0 {
				continue
			}
			if want == "" || md.EntityID == want {
				return md, nil
			}
		}
		return nil, fmt.Errorf("kexcore-saml: no IDPSSODescriptor for entityID %q", want)

	default:
		return nil, fmt.Errorf("kexcore-saml: unexpected metadata root %q", root.XMLName.Local)
	}
}

func ssoLocation(desc *saml.IDPSSODescriptor) string {
	if location := bindingLocation(desc.SingleSignOnServices, protocol.BindingRedirect); location != "" {
		return location
	}
	if location := bindingLocation(desc.SingleSignOnServices, protocol.BindingPost); location != "" {
		return location
	}
	if len(desc.SingleSignOnServices) > 0 {
		return desc.SingleSignOnServices[0].Location
	}
	return ""
}

func sloLocation(desc *saml.IDPSSODescriptor) string {
	if location := bindingLocation(desc.SingleLogoutServices, protocol.BindingRedirect); location != "" {
		return location
	}
	if location := bindingLocation(desc.SingleLogoutServices, protocol.BindingPost); location != "" {
		return location
	}
	return ""
}

func bindingLocation(endpoints []saml.Endpoint, binding protocol.Binding) string {
	for _, endpoint := range endpoints {
		if endpoint.Binding == string(binding) {
			return endpoint.Location
		}
	}
	return ""
}

func certificatesFromDescriptor(desc *saml.IDPSSODescriptor) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, key := range desc.KeyDescriptors {
		if key.Use == "encryption" {
			continue
		}
		for _, encoded := range key.KeyInfo.X509Data.X509Certificates {
			der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded.Data))
			if err != nil {
				return nil, fmt.Errorf("kexcore-saml: decode IdP certificate: %w", err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("kexcore-saml: parse IdP certificate: %w", err)
			}
			certs = append(certs, cert)
		}
	}
	return certs, nil
}

func parseCertificates(values []string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		rest := []byte(value)
		foundPEM := false
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			foundPEM = true
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("kexcore-saml: parse IdP certificate: %w", err)
			}
			certs = append(certs, cert)
		}
		if foundPEM {
			continue
		}

		der, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("kexcore-saml: certificate is neither PEM nor base64 DER: %w", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("kexcore-saml: parse IdP certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func dedupeCertificates(certs []*x509.Certificate) []*x509.Certificate {
	seen := make(map[string]struct{}, len(certs))
	out := certs[:0]
	for _, cert := range certs {
		key := string(cert.Raw)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, cert)
	}
	return out
}

// normalizedDescriptor builds the EntityDescriptor the engine validates
// against. It carries only the endpoints and signing certificates that were
// resolved above.
func normalizedDescriptor(entityID, ssoURL, sloURL string, certs []*x509.Certificate) *saml.EntityDescriptor {
	keyDescriptors := make([]saml.KeyDescriptor, 0, len(certs))
	for _, cert := range certs {
		keyDescriptors = append(keyDescriptors, saml.KeyDescriptor{
			Use: "signing",
			KeyInfo: saml.KeyInfo{
				X509Data: saml.X509Data{
					X509Certificates: []saml.X509Certificate{{
						Data: base64.StdEncoding.EncodeToString(cert.Raw),
					}},
				},
			},
		})
	}

	desc := saml.IDPSSODescriptor{
		SSODescriptor: saml.SSODescriptor{
			RoleDescriptor: saml.RoleDescriptor{
				ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
				KeyDescriptors:             keyDescriptors,
			},
		},
		SingleSignOnServices: []saml.Endpoint{{
			Binding:  string(protocol.BindingRedirect),
			Location: ssoURL,
		}},
	}
	if sloURL != "" {
		desc.SingleLogoutServices = []saml.Endpoint{{
			Binding:  string(protocol.BindingRedirect),
			Location: sloURL,
		}}
	}

	return &saml.EntityDescriptor{
		EntityID:          entityID,
		IDPSSODescriptors: []saml.IDPSSODescriptor{desc},
	}
}
