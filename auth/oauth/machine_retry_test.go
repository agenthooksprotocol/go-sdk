package oauth

import (
	"net/http"
	"testing"

	"github.com/agenthooksprotocol/go-sdk/auth"
)

func TestClientCredentialsTransientReissueWithoutLogin(t *testing.T) {
	for _, mode := range []string{"temporary", "non-oauth"} {
		t.Run(mode, func(t *testing.T) {
			f, p, r := setup(t, "client_credentials")
			first, err := p.Credential(budget(t), r)
			if err != nil {
				t.Fatal(err)
			}
			f.mode.Store(mode)
			_, err = p.Challenge(budget(t), r, auth.Challenge{StatusCode: http.StatusUnauthorized, Attempt: first.Attempt})
			assertCode(t, err, auth.CodeProviderFailed)
			stored, err := f.store.Load(budget(t), first.Attempt.(attempted).key)
			if err != nil || stored == nil || stored.RefreshToken == "" {
				t.Fatal("transient machine failure discarded grant")
			}
			f.mode.Store("ok")
			next, err := p.Prepare(budget(t), r)
			if err != nil || next.Credential == nil || next.Login != nil {
				t.Fatalf("machine reissue requested login: %v", err)
			}
			if f.refreshCalls.Load() != 0 || f.tokenCalls.Load() != 3 {
				t.Fatal("machine grant did not reissue noninteractively")
			}
			if anyPending(f.store) {
				t.Fatal("machine failure allocated pending consent")
			}
		})
	}
}
