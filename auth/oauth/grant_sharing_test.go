package oauth

import (
	"context"
	"errors"
	"testing"

	"github.com/agenthooksprotocol/go-sdk/auth"
)

func TestGrantSharingRequiresPartitionAndIndependentApproval(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(map[bool]string{false: "isolated", true: "shared"}[shared], func(t *testing.T) {
			f, p, event := setup(t, "authorization_code_pkce")
			original := p.options.SelectClient
			approveUpload := true
			p.options.SelectClient = func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
				if r.Purpose == auth.Upload && !approveUpload {
					return ClientConfig{}, errors.New("upload not approved")
				}
				c, err := original(ctx, r, issuers, resource)
				if shared {
					c.GrantPartition = "host-approved-shared-consent"
				}
				return c, err
			}
			finishLogin(t, p, event)
			upload := event
			upload.Purpose = auth.Upload
			approveUpload = false
			if result, err := p.Prepare(budget(t), upload); err == nil || result.Credential != nil {
				t.Fatal("event consent authorized unapproved upload")
			}
			approveUpload = true
			result, err := p.Prepare(budget(t), upload)
			if err != nil {
				t.Fatal(err)
			}
			if shared {
				if result.Credential == nil || result.Login != nil || f.tokenCalls.Load() != 1 {
					t.Fatal("explicit shared partition failed to reuse approved consent")
				}
			} else {
				if result.Login == nil || result.Credential != nil {
					t.Fatal("default partition leaked event consent into upload")
				}
				if err := p.Cancel(budget(t), upload, result.Login); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
