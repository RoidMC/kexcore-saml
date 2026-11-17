package sp

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
	"github.com/roidmc/kexcore-saml/pkg/protocol"
)

// Config describes one SAML Service Provider.
//
// One Config corresponds to one (tenant, identity provider) pair: EntityID
// and ACSURL are unique per pair, which is what keeps a response issued for
// one tenant from being replayed into another.
type Config struct {
	// EntityID is the SP's SAML entity identifier, for example
	// https://id.example.com/saml/sp/acme/okta.
	EntityID string
	// ACSURL is the absolute URL of the Assertion Consumer Service.
	ACSURL string
	// SLOURL is the optional absolute URL of the Single Logout Service.
	SLOURL string
	// MetadataURL is the optional public location of the SP metadata.
	MetadataURL string

	// IdP describes the identity provider this SP trusts.
	IdP IdPConfig

	// AllowIDPInitiated accepts unsolicited responses, which carry no
	// InResponseTo. Off by default: an IdP-initiated response cannot be tied
	// to a login the SP started.
	AllowIDPInitiated bool

	// AllowSHA1 permits SHA-1 signatures from the identity provider. Off by
	// default; enable it only for a legacy IdP that cannot do better.
	AllowSHA1 bool

	// NameIDFormat is requested in AuthnRequests. Empty leaves the
	// NameIDPolicy unspecified, which most IdPs accept.
	NameIDFormat protocol.NameIDFormat

	// Key and Certificate sign AuthnRequests and are published in the SP
	// metadata. Optional: many IdPs do not require signed requests.
	Key         crypto.Signer
	Certificate *x509.Certificate

	// EncryptionKey and EncryptionCertificate decrypt encrypted assertions.
	// Optional. EncryptionKey must be an RSA key.
	EncryptionKey         *rsa.PrivateKey
	EncryptionCertificate *x509.Certificate

	// DecryptionKeys are tried after EncryptionKey (or Key) while rotating
	// the SP encryption key.
	DecryptionKeys []*rsa.PrivateKey

	// ReplayCache records consumed assertion IDs. It must be shared by every
	// instance that accepts assertions for this SP. When nil, an in-memory
	// cache is used, which is only safe for a single instance.
	ReplayCache ReplayCache

	// MetadataValidDuration sets validUntil on the generated SP metadata.
	// Zero uses the engine default.
	MetadataValidDuration time.Duration

	// Clock overrides the time source, mainly for tests.
	Clock *dsig.Clock
}

// IdPConfig is the identity provider side of a Config.
type IdPConfig struct {
	// EntityID selects the identity provider inside an EntitiesDescriptor
	// and, when no metadata is supplied, names the IdP explicitly. Optional
	// when MetadataXML contains exactly one IdP.
	EntityID string

	// MetadataXML is the raw IdP metadata document. EntityDescriptor and
	// EntitiesDescriptor are both accepted. It is validated with
	// pkg/xmlsig before parsing.
	MetadataXML []byte

	// SSOURL overrides the SingleSignOnService location from the metadata.
	// Required when MetadataXML is empty.
	SSOURL string

	// SLOURL overrides the SingleLogoutService location from the metadata.
	SLOURL string

	// Certificates are PEM or base64 DER encoded IdP signing certificates.
	// They are added to the certificates found in MetadataXML and are
	// required when MetadataXML is empty.
	Certificates []string
}

// ReplayCache is the same contract as saml.AssertionReplayCache. Every
// implementation must be safe for concurrent use and, in a multi-instance
// deployment, shared (Redis, SQL) across instances.
type ReplayCache interface {
	// Consume records assertionID until expiresAt. It returns ErrReplay when
	// the ID was already recorded.
	Consume(assertionID string, expiresAt time.Time) error
}
