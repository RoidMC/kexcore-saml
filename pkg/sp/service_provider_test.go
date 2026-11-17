package sp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/roidmc/kexcore-saml/pkg/protocol"
)

const (
	testEntityID    = "https://sp.example.com/saml/sp/acme/okta"
	testACSURL      = "https://sp.example.com/saml/sp/acme/okta/acs"
	testIdPEntityID = "https://idp.example.com/metadata"
	testIdPSSOURL   = "https://idp.example.com/sso"
)

func testIdPMetadata(t *testing.T) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-idp"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return []byte(fmt.Sprintf(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`, testIdPEntityID, base64.StdEncoding.EncodeToString(der), testIdPSSOURL))
}

func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		EntityID: testEntityID,
		ACSURL:   testACSURL,
		IdP: IdPConfig{
			EntityID:    testIdPEntityID,
			MetadataXML: testIdPMetadata(t),
		},
	}
}

func newTestSP(t *testing.T) *ServiceProvider {
	t.Helper()
	sp, err := New(testConfig(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return sp
}

func TestNew_Validation(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, ErrMissingEntityID) {
		t.Fatalf("empty config error = %v, want ErrMissingEntityID", err)
	}

	if _, err := New(Config{EntityID: testEntityID}); !errors.Is(err, ErrMissingACSURL) {
		t.Fatalf("missing ACS error = %v, want ErrMissingACSURL", err)
	}

	if _, err := New(Config{EntityID: testEntityID, ACSURL: testACSURL}); !errors.Is(err, ErrMissingIdP) {
		t.Fatalf("missing IdP error = %v, want ErrMissingIdP", err)
	}

	cfg := testConfig(t)
	cfg.ACSURL = "/relative"
	if _, err := New(cfg); !errors.Is(err, ErrInvalidACSURL) {
		t.Fatalf("relative ACS error = %v, want ErrInvalidACSURL", err)
	}
}

func TestAuthnRequest(t *testing.T) {
	sp := newTestSP(t)

	rawURL, requestID, err := sp.AuthnRequest("state-123")
	if err != nil {
		t.Fatalf("AuthnRequest: %v", err)
	}
	if requestID == "" {
		t.Fatal("AuthnRequest returned an empty request ID")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse redirect URL: %v", err)
	}
	if parsed.Host != "idp.example.com" || parsed.Path != "/sso" {
		t.Fatalf("redirect target = %s, want idp.example.com/sso", rawURL)
	}

	query := parsed.Query()
	if query.Get("SAMLRequest") == "" {
		t.Fatal("redirect URL has no SAMLRequest")
	}
	if got := query.Get("RelayState"); got != "state-123" {
		t.Fatalf("RelayState = %q, want state-123", got)
	}
}

func TestMetadata(t *testing.T) {
	sp := newTestSP(t)

	raw, err := sp.Metadata()
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}

	var descriptor saml.EntityDescriptor
	if err := xml.Unmarshal(raw, &descriptor); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if descriptor.EntityID != testEntityID {
		t.Fatalf("entityID = %q, want %q", descriptor.EntityID, testEntityID)
	}
	if len(descriptor.SPSSODescriptors) != 1 {
		t.Fatalf("SPSSODescriptors = %d, want 1", len(descriptor.SPSSODescriptors))
	}

	services := descriptor.SPSSODescriptors[0].AssertionConsumerServices
	if len(services) != 1 || services[0].Location != testACSURL {
		t.Fatalf("ACS services = %+v, want one at %s", services, testACSURL)
	}
	if services[0].Binding != saml.HTTPPostBinding {
		t.Fatalf("ACS binding = %q, want HTTP-POST", services[0].Binding)
	}
}

func TestParseResponseXML_RejectsUnsigned(t *testing.T) {
	sp := newTestSP(t)

	response := []byte(fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response1" Version="2.0" IssueInstant="%s">
  <saml:Issuer>%s</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
</samlp:Response>`, time.Now().UTC().Format(time.RFC3339), testIdPEntityID))

	if _, err := sp.ParseResponseXML(response, nil, nil); err == nil {
		t.Fatal("ParseResponseXML accepted an unsigned response")
	}
}

func TestParseResponseXML_RejectsGarbage(t *testing.T) {
	sp := newTestSP(t)
	if _, err := sp.ParseResponseXML([]byte("not xml"), nil, nil); err == nil {
		t.Fatal("ParseResponseXML accepted a non-XML document")
	}
}

func TestIdentityFromAssertion(t *testing.T) {
	expires := time.Now().Add(time.Hour)
	assertion := &saml.Assertion{
		Issuer: saml.Issuer{Value: testIdPEntityID},
		Subject: &saml.Subject{
			NameID: &saml.NameID{
				Value:  "user@example.com",
				Format: string(protocol.NameIDFormatEmailAddress),
			},
			SubjectConfirmations: []saml.SubjectConfirmation{{
				SubjectConfirmationData: &saml.SubjectConfirmationData{NotOnOrAfter: expires},
			}},
		},
		AuthnStatements: []saml.AuthnStatement{{SessionIndex: "session-1"}},
		AttributeStatements: []saml.AttributeStatement{{
			Attributes: []saml.Attribute{
				{
					Name:   "urn:oid:1.2.840.113549.1.9.1",
					Values: []saml.AttributeValue{{Value: "user@example.com"}},
				},
				{
					Name:   "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
					Values: []saml.AttributeValue{{Value: "admins"}, {Value: "staff"}},
				},
			},
		}},
	}

	identity := identityFromAssertion(assertion)
	if identity.NameID != "user@example.com" {
		t.Fatalf("NameID = %q", identity.NameID)
	}
	if identity.Email() != "user@example.com" {
		t.Fatalf("Email() = %q", identity.Email())
	}
	if groups := identity.Groups(); len(groups) != 2 || groups[0] != "admins" || groups[1] != "staff" {
		t.Fatalf("Groups() = %v", groups)
	}
	if identity.SessionIndex != "session-1" {
		t.Fatalf("SessionIndex = %q", identity.SessionIndex)
	}
	if !identity.NotOnOrAfter.Equal(expires) {
		t.Fatalf("NotOnOrAfter = %v, want %v", identity.NotOnOrAfter, expires)
	}
}

func TestMemoryReplayCache(t *testing.T) {
	cache := NewMemoryReplayCache()
	expires := time.Now().Add(time.Minute)

	if err := cache.Consume("assertion-1", expires); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if err := cache.Consume("assertion-1", expires); !errors.Is(err, ErrReplay) {
		t.Fatalf("second Consume = %v, want ErrReplay", err)
	}
}

func TestFetchMetadata_RequiresHTTPS(t *testing.T) {
	_, err := FetchMetadata(t.Context(), "http://idp.example.com/metadata", FetchOptions{})
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("FetchMetadata(http) = %v, want https requirement", err)
	}
}

func TestParseCertificates_PEM(t *testing.T) {
	metadata := string(testIdPMetadata(t))
	const open = "<ds:X509Certificate>"
	start := strings.Index(metadata, open) + len(open)
	end := strings.Index(metadata[start:], "</ds:X509Certificate>")
	if start < len(open) || end < 0 {
		t.Fatal("test metadata has no certificate")
	}
	der, err := base64.StdEncoding.DecodeString(metadata[start : start+end])
	if err != nil {
		t.Fatalf("decode certificate: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	certs, err := parseCertificates([]string{string(pemBytes)})
	if err != nil {
		t.Fatalf("parseCertificates: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("certificates = %d, want 1", len(certs))
	}
}
