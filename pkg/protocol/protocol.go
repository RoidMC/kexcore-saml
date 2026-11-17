// Package protocol holds SAML constants and types shared by the service
// provider engine and the future identity provider engine.
//
// It deliberately has no dependency on the host application or on the HTTP
// layer: an Identity is the only thing that crosses the protocol boundary.
package protocol

import "time"

// NameIDFormat values defined by SAML 2.0.
type NameIDFormat string

const (
	NameIDFormatUnspecified  NameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	NameIDFormatEmailAddress NameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDFormatPersistent   NameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	NameIDFormatTransient    NameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
)

// Binding values used by the SP engine.
type Binding string

const (
	BindingRedirect Binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	BindingPost     Binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
)

// Canonical attribute names.
//
// Identity providers disagree on how attributes are named: some send the OID,
// some send a Microsoft claim URI, some send a friendly name. Mapping to a
// small canonical set keeps host code from matching on dozens of spellings.
const (
	AttrEmail       = "email"
	AttrDisplayName = "displayName"
	AttrUID         = "uid"
	AttrGroups      = "groups"
)

var attributeAliases = map[string]string{
	"mail":                              AttrEmail,
	"urn:oid:1.2.840.113549.1.9.1":      AttrEmail,
	"urn:oid:0.9.2342.19200300.100.1.3": AttrEmail,
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": AttrEmail,
	"http://schemas.xmlsoap.org/claims/EmailAddress":                     AttrEmail,

	"urn:oid:2.16.840.1.113730.1.1":                              AttrDisplayName,
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": AttrDisplayName,

	"urn:oid:0.9.2342.19200300.100.1.1": AttrUID,
	"urn:oid:2.5.4.42":                  "givenName",
	"urn:oid:2.5.4.4":                   "sn",
	"urn:oid:2.5.4.3":                   "cn",

	"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups": AttrGroups,
	"http://schemas.xmlsoap.org/claims/Group":                        AttrGroups,
	"urn:oid:1.3.6.1.4.1.5923.1.5.1.1":                               "eduPersonAffiliation",
}

// CanonicalAttribute returns the canonical name for a SAML attribute, or the
// input unchanged when it is not a known alias.
func CanonicalAttribute(name string) string {
	if canonical, ok := attributeAliases[name]; ok {
		return canonical
	}
	return name
}

// Identity is the protocol-neutral result of a successful assertion exchange.
//
// Attributes contains both the names as sent by the identity provider and
// their canonical aliases, so callers may look either spelling up.
type Identity struct {
	NameID       string
	NameIDFormat string
	SessionIndex string
	Issuer       string
	NotOnOrAfter time.Time
	Attributes   map[string][]string
}

// Values returns all values of an attribute, trying the given name and then
// its canonical alias.
func (i *Identity) Values(name string) []string {
	if i == nil || len(i.Attributes) == 0 {
		return nil
	}
	if values, ok := i.Attributes[name]; ok {
		return values
	}
	return i.Attributes[CanonicalAttribute(name)]
}

// Value returns the first value of an attribute, or the empty string.
func (i *Identity) Value(name string) string {
	values := i.Values(name)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// Email returns the canonical email attribute, if the identity provider sent
// one.
func (i *Identity) Email() string { return i.Value(AttrEmail) }

// DisplayName returns the canonical display name attribute, if present.
func (i *Identity) DisplayName() string { return i.Value(AttrDisplayName) }

// Groups returns the canonical group attribute, if present.
func (i *Identity) Groups() []string { return i.Values(AttrGroups) }
