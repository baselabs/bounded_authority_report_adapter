# Security policy

## Supported versions

The published `0.2.x` line is supported. The library is a holder-side signer: it never holds a
private key (callers supply a key handle), and every sign path verifies its own output against the
public key before returning, so a misconfigured signer fails loudly rather than emitting an
unverifiable signature.

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting / security-advisory flow for
`baselabs/bounded_authority_report_adapter`. Do not open a public issue containing an exploit,
credential, private key, or unreleased vulnerability detail.

A report should identify the affected version or commit, the violated property, a minimal
value-free reproduction, and the expected security outcome. We will acknowledge, triage, remediate,
and coordinate disclosure through the private advisory.
