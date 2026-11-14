# Releasing SignaCore

A release tag runs the CI workflow, publishes the container image to GHCR, and creates the
GitHub Release with the image digest. The workflow uses its short-lived `GITHUB_TOKEN` for
publishing.

## Cut a release

1. Confirm the commit you want to release is on `main`. Check its ancestry before creating
   the tag. The workflow validates the tag format.
2. Tag it and push the tag:

   ```bash
   git tag v1.2.0 <commit-on-main>     # or v1.2.0-rc.1 for a release candidate
   git push origin v1.2.0
   ```

3. Watch the **CI** workflow and verify that the GitHub Release records the published image digest.

A push to `main` runs the verification jobs. Publishing runs on release tags.

## Version rules

- Release tags match `vMAJOR.MINOR.PATCH` or `vMAJOR.MINOR.PATCH-rc.NUMBER`. The GitHub Release
  takes its title from the Git tag. The image takes the version without the `v` prefix.
- Stable tags also move the stable minor channel and `latest`.
- `rc` tags publish a prerelease image and a prerelease on GitHub. The stable channels move on
  stable releases.

## What must pass before publishing

| Job | Verification |
| --- | --- |
| `build-test` | The solution builds, unit and integration tests pass, and the container image passes scanning and smoke tests. |
| `database-contracts` | The PostgreSQL/SQLite contract matrix passes. |
| `container-platforms` | The image builds for AMD64 and ARM64. |
| `publish-container` | The image is pullable from GHCR and its digest is recorded. |

If image publishing succeeds and GitHub Release creation fails, rerun the workflow for the same
tag to finish creating the release. An existing GitHub Release keeps its notes on a rerun. To
correct a release, publish a new version.
