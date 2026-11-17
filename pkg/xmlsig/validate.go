// Package xmlsig centralises the XML hardening applied before any SAML
// document is parsed.
//
// SAML is an XML protocol and XML has a long history of parser-differential
// attacks: DTD and entity tricks, duplicated attributes, namespace and prefix
// rewrites. Nothing here attempts to implement XML signature verification;
// that lives in the service provider engine, which delegates to
// goxmldsig. This package only ensures the bytes are the bytes that were
// signed.
package xmlsig

import (
	"bytes"
	"fmt"

	validator "github.com/mattermost/xml-roundtrip-validator"
)

// Validate rejects a document that does not survive an XML round trip. It is
// mandatory for every externally supplied SAML document: identity provider
// metadata, Responses and Assertions.
func Validate(data []byte) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return fmt.Errorf("xmlsig: empty document")
	}
	if err := validator.Validate(bytes.NewReader(data)); err != nil {
		return fmt.Errorf("xmlsig: round-trip validation failed: %w", err)
	}
	return nil
}
