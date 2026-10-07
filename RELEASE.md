# Releases

This SDK releases independently of the other SDKs. Release Please maintains the
changelog and version manifest, then creates root tags such as `v0.1.0` and GitHub
releases. The module path remains `github.com/agenthooksprotocol/go-sdk`; no runtime
version file or registry publishing job is needed.

## Repository setup

1. Enable GitHub Actions and allow the actions used by the existing CI and release
   workflows. Enable **Allow GitHub Actions to create and approve pull requests**
   under **Settings → Actions → General → Workflow permissions** where permitted
   by organization policy.
2. Create an organization-approved fine-grained personal access token scoped only
   to this repository, with **Contents: Read and write** and **Pull requests: Read
   and write**. Store it as the Actions repository secret `RELEASE_PLEASE_TOKEN`.
   Its owner must retain repository access; renew the token before it expires.
   A PAT, rather than `GITHUB_TOKEN`, allows release PRs to trigger normal CI.
3. Retain required CI checks and normal review rules for `main`. Ensure repository
   rules allow the token owner to create release PR branches, `v*` tags, and GitHub
   releases. The existing CI toolchains and pinned canonical fixtures must be
   available; release creation is blocked if that CI fails.

## Lifecycle

- Conventional commits on `main` drive release PRs. Every push to `main` runs the
  existing CI through `workflow_call`; only after it succeeds does Release Please
  create/update a release PR or create the GitHub release for a merged release PR.
  The ordinary CI workflow remains enabled as well.
- Review and merge the generated release PR normally. The manifest starts at
  `0.0.0`, a sentinel indicating no previous release. `initial-version: 0.1.0`
  affects only the first release; subsequent versions follow conventional commits.
  Release Please maintains the manifest at the last released version thereafter.
- A merged release PR is tagged by Release Please directly in this workflow.
  There is no separate tag-triggered workflow, registry upload, registry probe,
  automated install check, or post-release verification job.
- Go modules are distributed from version-control tags. No registry account,
  trusted-publisher/OIDC configuration, `release` environment, or bootstrap upload
  is required. Public consumers and Go proxies can resolve the public repository's
  semantic-version tag on demand. Never move or replace a released tag.

Official references: [Release Please action and PAT setup](https://github.com/googleapis/release-please-action),
[manifest configuration and bootstrap behavior](https://github.com/googleapis/release-please/blob/main/docs/manifest-releaser.md),
and [publishing Go modules](https://go.dev/doc/modules/publishing).
