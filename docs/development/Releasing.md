# Releasing SignaCore

A release tag does everything: the same `ci.yml` run that tests the commit also publishes the
container image and the GitHub Release. There is no manual publishing step and no long-lived
publishing credential in this repository.

The `SignaCore.Client.AspNetCore` NuGet package is **not published automatically**. The package is
in its deprecation window ([ADR 0010](../adr/0010-standards-conformant-oidc-and-generic-client-integration.md)
stage 5): the NuGet.org listing is flagged deprecated and features are frozen, so pushing a new
version per release tag would only burn version numbers nobody should adopt. CI still packs the
client package with the tag's exact version and runs the package-only consumption smoke, and the
nupkg stays a workflow artifact; the suspended publishing job is kept in `ci.yml` so a
security-fix release can ship by restoring one condition (see
[NuGet publishing (suspended)](#nuget-publishing-suspended)).

## Cut a release

1. Confirm the commit you want to release is on `main`. Check its ancestry before creating
   the tag; the workflow validates the tag format but does not enforce ancestry.
2. Tag it and push the tag:

   ```bash
   git tag v1.2.0 <commit-on-main>     # or v1.2.0-rc.1 for a release candidate
   git push origin v1.2.0
   ```

3. Watch the **CI** workflow. A successful run ends with two published outputs: the GHCR
   image and the GitHub Release whose notes quote the image digest.

A push to `main` runs the same tests and packs the same package, but publishes nothing: the package
exists only as a workflow build output with a non-publishable `0.0.0-edge.*` version, and no image
is pushed. Only a release tag publishes.

## Version rules

- A release tag starts with `v`, and the tag without the prefix **is** the image's semver tag and
  the packed client package's version: `v1.2.0` publishes image version `1.2.0` and packs (does
  not publish) the client package as `1.2.0`; `v1.2.0-rc.1` does the same for the pre-release
  `1.2.0-rc.1` (NuGet treats any prerelease label as a pre-release, so nothing extra would be
  needed if publishing resumes). The GitHub Release takes its title from the tag, `v1.2.0`.
- A release tag must match `vMAJOR.MINOR.PATCH` or `vMAJOR.MINOR.PATCH-rc.NUMBER` exactly. The
  container job and the pack step both enforce the same regular expression, which also rules out
  build metadata (`+`), since NuGet discards it and two tags would collide on one package slot.
- `rc` tags publish a pre-release image and never move `latest`, the stable minor channel, or
  the GitHub "latest" release — exactly as the image rules already do.

## What must pass before anything is published

| Gate | It proves |
| --- | --- |
| `build-test` | The whole solution builds; unit, integration, contract, reference-BFF, and client-package tests pass; the image is built and scanned; the container smoke suite passes. |
| Pack + consumption smoke | The client package is packed from the tested sources, and a project that references nothing but the nupkg restores, builds, and boots against the pack output. |
| `database-contracts` | The PostgreSQL/SQLite contract matrix passes (a dependency of the image job). |
| `publish-container` | The image is on GHCR, pullable, with the digest recorded. |

A failure or cancellation anywhere above leaves the later jobs unrun, so nothing reaches GHCR
or the Release. While `publish-nuget` is suspended, no job holds a NuGet publishing credential;
the remaining publishing jobs (`publish-container`, `publish-release`) use only the workflow's
short-lived `GITHUB_TOKEN`.

## Order and repair

The jobs run in a fixed order: **tests → image → GitHub Release**. The release runs after the
image so its notes can quote the digest that was really published. If a run dies between the
image and the release, re-running the workflow for the same tag repairs the gap:

- an existing GitHub Release is left untouched, so hand-edited notes survive a re-run;
- the `latest` and semver image tags behave exactly as they did in the container-only era.

A published version is never deleted or replaced. If a release is wrong, publish a new version.

## NuGet publishing (suspended)

The `publish-nuget` job stays in `ci.yml` but is disabled (`if: ${{ false }}`) for the package's
deprecation window; nothing it does runs. To publish a security-fix package release, restore its
original condition — `github.event_name == 'push' && startsWith(github.ref, 'refs/tags/')` — on
`main` and cut a new release tag: GitHub takes the workflow file from the commit a run starts
from, so re-running an old run would keep the job suspended. The job then works exactly as it
did before it was suspended:

- it runs only after the container image is published, because a NuGet push is irreversible
  while the image can be re-pushed;
- it downloads the exact nupkg artifact that passed the tests and the consumption smoke —
  nothing is rebuilt in the job;
- an exact version already on NuGet.org is detected before the push and skipped as
  *already present* — the run then still verifies that the published version restores from the
  feed;
- it is the only job in the workflow that holds a publishing credential, acquired with
  **NuGet Trusted Publishing**: the job exchanges its GitHub OIDC token for a short-lived
  NuGet.org API key (`NuGet/login`, pinned to a commit SHA), so no long-lived secret exists in
  this repository. The key is passed to `dotnet nuget push` through the environment and never
  appears in a process argument or a log line. `id-token: write` is granted to that one job
  only, and only on tag pushes; the job checks out the repository with
  `persist-credentials: false`, so the checkout token is never in the workspace next to the
  publishing key. Every other job keeps the workflow's default `contents: read`; no
  pull-request run can reach a publishing credential at all;
- after the push, it restores the just-published version **from NuGet.org** through a NuGet
  cache that has never held a SignaCore package, builds the package-only consumer under
  `eng/tests/consumers/signacore-client-aspnetcore` against it, and boots it. NuGet.org makes a
  push restorable some time after accepting it, so the verification retries within an explicit
  budget (30 attempts, 30 seconds apart — above the indexing latency observed on this feed
  family). Exhausting the budget fails the job with a fixed message instead of hanging; to
  recover, confirm the version is visible on NuGet.org and re-run only that job.

## One-time NuGet.org configuration (maintainer)

These are account-side settings that cannot be changed from this repository:

1. GitHub: create the environment **`nuget.org`** on `philfanzhou/SignaCore` with no required
   reviewers. The environment exists only to bind the NuGet.org trusted-publishing policy; a
   release tag is itself the explicit maintainer decision, so no deployment review is
   interposed. Add the repository variable `NUGET_USER` (the NuGet.org account name that owns
   the package).
2. nuget.org: under *Account settings → Trusted Publishing*, add a policy binding repository
   `philfanzhou/SignaCore`, workflow `ci.yml`, and environment `nuget.org`.
3. Confirm the package id `SignaCore.Client.AspNetCore` is available (it was unregistered as of
   2026-09-30).

These settings already exist and stay in place, so re-enabling the suspended `publish-nuget` job
requires no account-side change; nothing else in the workflow depends on them while it is
suspended.

## Manual dry run

The consumption smoke is a plain script and works against any source:

```bash
dotnet pack src/SignaCore.Client.AspNetCore -c Release -p:Version=1.2.0-test -o artifacts/packages
eng/tests/published-package-consumption.sh \
  --version 1.2.0-test \
  --source "$(pwd)/artifacts/packages" \
  --consumer eng/tests/consumers/signacore-client-aspnetcore \
  --attempts 1
```
