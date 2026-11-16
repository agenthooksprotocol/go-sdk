# OAuth lifecycle test coverage

`sdk-auth-lifecycle.json` is an exact copy of the canonical protocol repository's
`conformance/draft/sdk-auth-lifecycle.json`. It contains fake credentials only.
Recovery, key and token-response vectors are executable inputs to
`TestRecoveryContractVectors`, `TestCanonicalGrantKeys` and
`TestCanonicalTokenResponses`. Token tests use verified TLS token endpoints and
coordinated host storage, including persisted narrowed-refresh inheritance.

The JSON `lifecycle` array is a coverage manifest, not an executable runner or
proof of runtime behavior. Its IDs map to these native tests:

| Lifecycle ID | Executable native test |
| --- | --- |
| `cached-token-metadata-outage` | `TestCachedUnboundUnsafeDeliveryAfterProviderRecreation` |
| `unbound-preemptive-unsafe-delivery` | `TestCachedUnboundUnsafeDeliveryAfterProviderRecreation` (event and upload through `auth.Route` + `auth.Do`) |
| `refresh-unknown-expiry-rotation` | `TestCanonicalTokenResponses/refresh-inherits-narrowed-grant`, `TestCanonicalTokenResponses/refresh-preserves-allowed-extra-scope` (cache reuse and subsequent rotated refresh) |
| `transient-refresh-failure` | `TestManagedTemporaryRefreshRetainsAndDefinitiveRejectionRepairs`, `TestLifecycleNonOAuthRefreshFailureRetainsRetry`, `TestManagedCancellationLeavesAmbiguityAndReleasesCoordination`, `TestManagedFailedRefreshCommitDoesNotReuseOldGeneration` |
| `client-credentials-transient-reissue` | `TestClientCredentialsTransientReissueWithoutLogin` |
| `host-owned-login-budget` | `TestLifecycleDispatchDoesNotOwnConsent` |
| `metadata-and-secret-rotation` | `TestMetadataCapabilityAndRuntimeSecretRotation`, `TestLifecycleCompletionUsesCurrentSecretAndPolicy` |
| `insufficient-scope-step-up` | `TestLifecycleAllowedStepUp`, `TestInsufficientScopeTransport`, `TestInsufficientScopeSafeRetryBound` |
| `configured-preset-no-protected-resource-metadata` | `TestCanonicalTokenResponses`, `TestMetadataCapabilityAndRuntimeSecretRotation` (unexpected PRM requests fail) |
| `explicit-shared-grant` | `TestGrantSharingRequiresPartitionAndIndependentApproval` |
| `invalid-callback-does-not-consume` | `TestManagedCallbackBindingAndNoImplicitConsent` |
| `loopback-redirect` | `TestLifecyclePendingRequirementsAndLiteralLoopback` |
| `narrowed-refresh-scope-inheritance` | `TestCanonicalTokenResponses` (both refresh vectors), `TestLifecycleRefreshUsesPreviousGrant` |
| `pending-scope-context-replacement` | `TestLifecyclePendingScopeContextReplacement` |
| `pending-budget-replacement` | `TestLifecyclePendingBudgetReplacement` |
| `scope-challenge-without-required-scope` | `TestLifecycleNoScopeChallengeUsesOnlyHostRequirement` |

Run the executable coverage from the SDK root:

```sh
go test ./auth/...
go test -race ./auth/...
```

These tests use native HTTP, policy and Store boundaries. No runtime test reads
from `/tmp` or requires the sibling protocol checkout for the lifecycle vectors.
