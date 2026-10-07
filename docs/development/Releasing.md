# Releasing SignaCore

A release tag does everything: the same `ci.yml` run that tests the commit also publishes the
container image, the NuGet package, and the GitHub Release. There is no manual publishing step
and no long-lived publishing credential in this repository.

## Cut a release

1. Confirm the commit you want to release is on `main`. Check its ancestry before creating
   the tag; the workflow validates the tag format but does not enforce ancestry.
2. Tag it and push the tag:

   ```bash
   git tag 1.2.0 <commit-on-main>      # or 1.2.0-rc.1 for a release candidate
   git push origin 1.2.0
   ```

3. Watch the **CI** workflow. A successful run ends with three published artifacts: the GHCR
   image, the `SignaCore.Client.AspNetCore` package on NuGet.org, and the GitHub Release whose
   notes quote the image digest and the package version.

A push to `main` runs the same tests and packs the same package, but publishes no NuGet package
or GitHub Release: the package exists only as a workflow artifact with a non-publishable `0.0.0-edge.*` version, and the
image is published only under the moving `edge` tag.

## Version rules

- The tag **is** the package version and the image's semver tag: `1.2.0` publishes `1.2.0`;
  `1.2.0-rc.1` publishes the pre-release `1.2.0-rc.1` (NuGet treats any prerelease label as a
   pre-release, so nothing extra is needed).
- A release tag must match `MAJOR.MINOR.PATCH` or `MAJOR.MINOR.PATCH-rc.NUMBER` exactly. The
  container job and the pack step both enforce the same regular expression, which also rules out
  build metadata (`+`), since NuGet discards it and two tags would collide on one package slot.
- `rc` tags publish a pre-release package and a pre-release image and never move `latest`, the
  stable minor channel, or the GitHub "latest" release — exactly as the image rules already do.

## What must pass before anything is published

| Gate | It proves |
| --- | --- |
| `build-test` | The whole solution builds; unit, integration, contract, reference-BFF, and client-package tests pass; the image is built and scanned; the container smoke suite passes. |
| Pack + consumption smoke | The client package is packed from the tested sources, and a project that references nothing but the nupkg restores, builds, and boots against the pack output. |
| `database-contracts` | The PostgreSQL/SQLite contract matrix passes (a dependency of the image job). |
| `publish-container` | The image is on GHCR, pullable, with the digest recorded. |
| `publish-nuget` | The exact artifact that passed the smoke is pushed; the published version then restores from NuGet.org itself through a clean cache. |

A failure or cancellation anywhere above leaves the later jobs unrun, so nothing reaches NuGet.org
or the Release. `publish-nuget` is the only job that holds a credential, and it acquires a
short-lived one (see below).

## Order and repair

The jobs run in a fixed order: **tests → image → NuGet package → GitHub Release**. The image comes
first because it is re-pushable; the NuGet push is not reversible, so it must not be the first
thing a broken run does. If a run dies between the image and the package, re-running the workflow
for the same tag repairs the gap:

- an exact version already on NuGet.org is detected before the push and skipped as
  *already present* — the run then still verifies that the published version restores from the
  feed;
- an existing GitHub Release is left untouched, so hand-edited notes survive a re-run;
- the image and `edge`/`latest` semantics are unchanged from the container-only era.

A published version is never deleted or replaced. If a release is wrong, publish a new version.

## Credentials

The package is published with **NuGet Trusted Publishing**: the `publish-nuget` job exchanges its
GitHub OIDC token for a short-lived NuGet.org API key (`NuGet/login`, pinned to a commit SHA), so
no long-lived secret exists in this repository. The key is passed to `dotnet nuget push` through
the environment and never appears in a process argument or a log line.

`id-token: write` is granted to that one job only, and only on tag pushes. The job checks out the
repository with `persist-credentials: false`, so the checkout token is never in the workspace next
to the publishing key. Every other job keeps the workflow's default `contents: read`; no
pull-request run can reach a publishing credential at all.

## Post-publish verification

Pushing is not the same as being installable. After the push, the workflow restores the just
published version **from NuGet.org** through a NuGet cache that has never held a SignaCore
package, builds the package-only consumer under `eng/tests/consumers/signacore-client-aspnetcore`
against it, and boots it. Nothing on the runner can make a broken or missing package look
installable.

NuGet.org makes a push restorable some time after accepting it, so the verification retries within
an explicit budget (30 attempts, 30 seconds apart — above the indexing latency observed on this
feed family). Exhausting the budget fails the job with a fixed message instead of hanging; to
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

Until the environment or the trusted-publishing policy exists, the `publish-nuget` job fails at
the credential step; everything before it still runs, so the image still publishes.

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
