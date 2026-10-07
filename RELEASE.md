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
2. Use the existing **Agent Hooks Protocol Bot** GitHub App. Install it on this
   repository with **Contents: read/write** and **Pull requests: read/write**.
   Set Actions variable **`RELEASE_APP_ID`** to its App ID and Actions secret
   **`RELEASE_APP_PRIVATE_KEY`** to a PEM private key generated in its settings.
   Organization-level values may be shared with just the four SDK repositories.
   The workflow mints a short-lived installation token scoped to this repository
   and those two permissions; it is revoked when the job ends. Release PRs,
   tags, and GitHub releases use the bot identity and trigger normal PR CI.
   No personal access token is needed. Keep branch protection enabled.
3. Retain required CI checks and normal review rules for `main`. Ensure repository
   rules allow the App installation to create release PR branches, `v*` tags, and GitHub
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

## Contract pin notification

After the complete **Release** workflow succeeds for a `main` push, the separate
`release-notify.yml` workflow sends a `sdk-released` repository dispatch to
`agenthooksprotocol/agent-hooks-protocol`. Go is distributed directly from its released Git tag. It also checks that a
non-draft, non-prerelease GitHub release has a stable version tag pointing at that
exact workflow run head, including annotated tag dereferencing. Ordinary Release
Please PR updates do not send a notification.

The contract receiver uses the repository, revision, and run ID in the notification
to propose released SDK pins in one bot PR. This is event-driven: there is no
schedule, registry probe, package installation, or additional publishing step.
The notifier does not check out or execute SDK code. Its repository token has only
Actions and Contents read access for release metadata; a separate short-lived App
token has only Contents write access to the contract repository for dispatch.

The existing `RELEASE_APP_ID` and `RELEASE_APP_PRIVATE_KEY` must identify an App
installed on **agenthooksprotocol/agent-hooks-protocol** with **Contents: read/write**,
in addition to its existing SDK installation. The notifier explicitly scopes the
App token to that target repository and revokes it at job completion. Installing
this workflow does not replay earlier releases (including the initial `0.1.0`);
initialize those pins through the contract receiver's manual workflow instead of
rerunning a publishing workflow.
