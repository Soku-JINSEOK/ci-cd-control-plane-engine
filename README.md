# Public Control-Plane Engine

This synthetic candidate contains reusable registry, pipeline, and publication
contracts. It contains no live repository, cloud, Project, issue, or operator
inventory. A private overlay may consume this interface only through a
separately reviewed compatibility contract.

The additive [provider-neutral execution sidecar](docs/execution-contracts.md)
defines execution requirements, adapter descriptors, normalized evidence, and
an executable `local-reference-v1` runner without changing pipeline v1.

Run `scripts/verify-public-contract.sh` for the repository-owned public
contract profile. It validates the publication surface, registry resolution,
adapter contracts, and Python tests, then writes deterministic
`public-contract-evidence-v1` semantic evidence. Provider run IDs, timestamps,
and other non-semantic execution metadata are intentionally excluded so the
same source SHA produces byte-identical evidence in Tokyo Cloud Build and the
informational public GitHub Actions check.

The candidate was produced from an explicit export allowlist and a newly
initialized Git history. Run the publication checker against an extracted
source tree before any publication approval.

<!-- Hosted Tokyo PR validation is bound via declarative control-plane trigger. -->
<!-- Trigger Tokyo hosted validation pilot run -->
<!-- Trigger verified Tokyo pipeline execution -->
<!-- Final trusted inline Tokyo pipeline pilot run -->
