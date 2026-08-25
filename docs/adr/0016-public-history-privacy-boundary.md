# 16. Public-history privacy boundary

Date: 2026-08-24

## Status

Accepted. Applies to the public source repository, every reachable commit and tag,
and package/source metadata.

## Context

An independent review found that historical source and commit descriptions named a
private consumer and described its deployment-specific signing and verification
topology. The public library contract does not require that information. Removing it
only from the current branch would leave it available through old commits and release
tags.

The separate `bounded_authority` runtime is also easy to conflate with the public
libraries. It is a private commercial application, not a public Hex package and not a
BARA dependency.

## Decision

1. Public BARA material uses protocol-generic roles: issuer, holder, verifier, request,
   envelope, and consumer application. It does not name private consumers, their
   transports, database fields, lifecycle labels, source paths, or deployment topology.
2. All public branches, tags, commit messages, paths, and tracked blobs are rewritten to
   satisfy that boundary. Release tags retain their version names but point to rewritten
   source identities.
3. A hash-based privacy gate scans tracked files and all reachable history. Hashes keep
   the prohibited private identifiers out of the public tree while retaining an
   executable tripwire.
4. BARA and BAP publication does not imply BA publication. BA remains private and may be
   distributed privately only after a separately authorized commercial release channel
   exists.

## Consequences

- Existing clones must re-clone or reset to the rewritten public history; old commit IDs
  and tag object IDs are intentionally invalidated.
- Public registry archives are separate immutable artifacts. They are audited separately;
  a new clean package version or registry-provider action requires its own release receipt.
- Generic protocol mechanics remain documented. Consumer-specific implementation detail
  stays only in its private owner repository.
