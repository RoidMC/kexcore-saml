// Package kexcoresaml is the module root for KexCore's SAML 2.0 SDK.
//
// Scope: inbound SAML only. KexCore acts as a Service Provider (SP): it sends
// AuthnRequests to a tenant's identity provider, consumes the returned
// assertions, and hands the resulting identity to the host application.
//
// The outbound Identity Provider role is deliberately not implemented here.
// Its seam lives in pkg/idp so that adding it later does not change the SP API
// or the host-facing provider contract.
//
// The package layout mirrors github.com/roidmc/kexcore-oidc:
//
//	pkg/protocol  protocol constants and types, no host dependency
//	pkg/sp        Service Provider engine (AuthnRequest, ACS, validation)
//	pkg/xmlsig    XML hardening applied before any SAML document is parsed
//	pkg/idp       reserved outbound IdP interfaces
//
// A host application (KexCore's UniAPI adapter) is expected to own tenancy,
// user storage, session issuance and HTTP routing. This module owns the SAML
// wire format and its security checks; it never imports the host.
package kexcoresaml
