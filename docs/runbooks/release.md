# Runbook: cutting a release, and verifying one

Two audiences. The first half is for whoever tags a release; the second is for an operator who
wants to know that what they are about to run is what this project published. The policy behind
both — what a version number promises, how long it is supported — is in
[`../releases.md`](../releases.md).

## Cutting a release

Everything below happens on `main`, in one pull request, before any tag exists.

1. **Bump the version.** Six files, all to the same number: the root `pyproject.toml`, the four
   workspace packages, and `appVersion` in `deploy/helm/icebergsst/Chart.yaml`. Bump the chart's
   own `version` too if any template changed.

   ```
   make version-check      # fails naming every file that disagrees
   ```

2. **Write the CHANGELOG entry.** Rename `## [Unreleased]` to `## [X.Y.Z] — YYYY-MM-DD` and add a
   fresh `Unreleased` above it. The entry *is* the release notes — the workflow extracts it and
   nothing is written twice — so it is the place to say what an operator has to do, not a list of
   commit subjects.

   A release that adds a migration must have a **Migrations** section. `make check` fails
   otherwise (`tests/test_release_invariants.py`), because "does this upgrade touch my database?"
   is the question an operator asks first and the one a changelog most often fails to answer.

3. **Merge, then tag the merge commit.**

   ```
   git switch main && git pull
   git tag -a v0.2.0 -m "v0.2.0"
   git push origin v0.2.0
   ```

   The tag is what triggers `release.yml`. Its first job re-checks the version agreement and the
   CHANGELOG entry *before* anything is built, because once an artifact is signed and pushed it is
   public and a bad release has to be superseded rather than withdrawn.

4. **Watch the workflow.** It publishes, in order: both role images (signed by digest, with an
   SBOM and build provenance attached), the Helm chart, and a GitHub release carrying the source
   archive, its signature bundle, the SBOMs, and `SHA256SUMS`.

5. **Verify the release yourself**, using the operator section below. A release nobody has
   verified is a signature nobody has tested.

### If the workflow fails halfway

Do not delete and re-push the tag: a moved tag is exactly the mutable-pointer problem signing
exists to solve, and anything already published is still signed against the old commit. Fix
forward — cut the next patch version — unless *nothing* was published, in which case
`workflow_dispatch` re-runs the whole thing for the same tag.

That dispatch input is validated as an **existing** `vX.Y.Z` tag before anything is checked out
from it, and every publishing job then uses the resolved ref rather than the string. A recovery
path that accepted a branch name would let a manual run publish untagged code over a release an
operator had already verified — the one thing `on: push: tags:` gives for free.

## Verifying a release

None of this requires trusting IcebergSST with a signing key. The images are signed with cosign's
**keyless** flow: the signature is bound to the GitHub workflow identity that produced it, and the
certificate that proves it was issued for the length of one job and then expired.

**The image:**

```
cosign verify \
  --certificate-identity-regexp '^https://github\.com/IcebergAI/IcebergSST/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/icebergai/icebergsst/api:0.2.0
```

The two `--certificate-*` flags are the check. Without them `cosign verify` confirms that
*somebody* signed the image, which is not a useful statement about anything.

**The build provenance** — that it was built from this repository, by that workflow, from that
commit:

```
gh attestation verify oci://ghcr.io/icebergai/icebergsst/api:0.2.0 --repo IcebergAI/IcebergSST
```

**The SBOM**, which is how to answer "does this release contain the library in that advisory?"
without rebuilding it:

```
cosign download attestation ghcr.io/icebergai/icebergsst/api:0.2.0 \
  | jq -r '.payload | @base64d | fromjson | .predicate' > api-sbom.spdx.json
```

**The chart:**

```
cosign verify \
  --certificate-identity-regexp '^https://github\.com/IcebergAI/IcebergSST/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/icebergai/icebergsst/charts/icebergsst:0.2.0
```

**The source archive**, using the bundle published beside it:

```
cosign verify-blob \
  --bundle icebergsst-0.2.0-source.tar.gz.cosign.bundle \
  --certificate-identity-regexp '^https://github\.com/IcebergAI/IcebergSST/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  icebergsst-0.2.0-source.tar.gz
```

`SHA256SUMS` is published for convenience and is **not** a substitute for any of the above: it is
published by the same party as the files it describes, so it detects a corrupted download and
nothing else.

### Pin by digest in production

A tag can be moved; a digest cannot. Once a release is verified, deploy the digest:

```yaml
image:
  api:
    repository: ghcr.io/icebergai/icebergsst/api
    tag: ""                                  # unset, so the digest is what resolves
    digest: sha256:…
```

That also makes the next upgrade a deliberate act rather than something a re-pulled tag does on
its own during an unrelated pod restart.

## Upgrading

The supported paths, the migration compatibility rule, and what rollback can and cannot recover
are in [`../releases.md`](../releases.md). The order that makes it survivable is short enough to
repeat here:

1. Back up the database, and **restore the backup into a scratch database** to prove it works
   ([`backup-restore.md`](./backup-restore.md)). An unverified backup is a plan, not a backup.
2. Read the release's **Migrations** and **Operator actions** sections.
3. Upgrade the API — which runs the migration in a pre-upgrade Job — then the engines.
4. To roll back: engines first, then the API. Only touch the schema if the notes say the change
   is not backward-compatible, and prefer restoring the backup where the data matters.
