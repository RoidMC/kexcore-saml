package sp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
)

// staticSPProvider returns the same SP metadata for every lookup. It exists
// only so the test identity provider can serve the SP we are testing.
type staticSPProvider struct {
	metadata *saml.EntityDescriptor
}

func (p staticSPProvider) GetServiceProvider(*http.Request, string) (*saml.EntityDescriptor, error) {
	return p.metadata, nil
}

// TestParseResponse_SignedRoundTrip drives the full path: SP builds an
// AuthnRequest, a real IdP implementation signs a Response, and the SP accepts
// it. It is the positive counterpart to the rejection tests.
func TestParseResponse_SignedRoundTrip(t *testing.T) {
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
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	ssoURL, _ := url.Parse(testIdPSSOURL)
	metadataURL, _ := url.Parse(testIdPEntityID)
	idp := &saml.IdentityProvider{
		Key:         key,
		Certificate: cert,
		SSOURL:      *ssoURL,
		MetadataURL: *metadataURL,
	}

	rawIdPMetadata, err := xml.Marshal(idp.Metadata())
	if err != nil {
		t.Fatalf("marshal IdP metadata: %v", err)
	}

	spEngine, err := New(Config{
		EntityID: testEntityID,
		ACSURL:   testACSURL,
		IdP: IdPConfig{
			EntityID:    testIdPEntityID,
			MetadataXML: rawIdPMetadata,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	redirectURL, requestID, err := spEngine.AuthnRequest("relay-state")
	if err != nil {
		t.Fatalf("AuthnRequest: %v", err)
	}

	rawSPMetadata, err := spEngine.Metadata()
	if err != nil {
		t.Fatalf("SP metadata: %v", err)
	}
	var spMetadata saml.EntityDescriptor
	if err := xml.Unmarshal(rawSPMetadata, &spMetadata); err != nil {
		t.Fatalf("unmarshal SP metadata: %v", err)
	}
	idp.ServiceProviderProvider = staticSPProvider{metadata: &spMetadata}

	idpRequest, err := saml.NewIdpAuthnRequest(idp, mustRequest(t, http.MethodGet, redirectURL))
	if err != nil {
		t.Fatalf("NewIdpAuthnRequest: %v", err)
	}
	if err := idpRequest.Validate(); err != nil {
		t.Fatalf("IdP validate: %v", err)
	}

	session := &saml.Session{
		ID:           "session-1",
		CreateTime:   time.Now(),
		ExpireTime:   time.Now().Add(time.Hour),
		Index:        "session-index-1",
		NameID:       "user@example.com",
		NameIDFormat: string(saml.EmailAddressNameIDFormat),
		UserEmail:    "user@example.com",
		UserName:     "user",
	}
	if err := (saml.DefaultAssertionMaker{}).MakeAssertion(idpRequest, session); err != nil {
		t.Fatalf("MakeAssertion: %v", err)
	}
	if err := idpRequest.MakeResponse(); err != nil {
		t.Fatalf("MakeResponse: %v", err)
	}

	document := etree.NewDocument()
	document.SetRoot(idpRequest.ResponseEl.Copy())
	rawResponse, err := document.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize response: %v", err)
	}

	form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(rawResponse)}}
	request := httptest.NewRequest(http.MethodPost, testACSURL, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	identity, err := spEngine.ParseResponse(request, []string{requestID})
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if identity.NameID != "user@example.com" {
		t.Fatalf("NameID = %q, want user@example.com", identity.NameID)
	}
	if identity.Email() != "user@example.com" {
		t.Fatalf("Email = %q, want user@example.com", identity.Email())
	}
}

func TestParseResponse_SignedRoundTrip_RejectsReplay(t *testing.T) {
	// Reuse the setup from the positive test by building the same artifacts
	// twice through a helper would hide which step failed; instead this test
	// asserts the replay sentinel on the cache the engine uses.
	cache := NewMemoryReplayCache()
	if err := cache.Consume("assertion-x", time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if err := cache.Consume("assertion-x", time.Now().Add(time.Minute)); err == nil {
		t.Fatal("replay was accepted")
	}
}

func mustRequest(t *testing.T, method, rawURL string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return request
}
