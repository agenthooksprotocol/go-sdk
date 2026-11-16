package oauth

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/agenthooksprotocol/go-sdk/auth"
)

func TestManagedPendingCopiesAreRedactedAndCannotComplete(t *testing.T) {
	for _, cancelOriginal := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelOriginal), func(t *testing.T) {
			f, p, r := setup(t, "authorization_code_pkce")
			ctx := budget(t)
			prepared, err := p.Prepare(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			original := prepared.Login
			copied := *original
			for _, text := range []string{fmt.Sprintf("%+v", copied), fmt.Sprintf("%#v", copied), fmt.Sprintf("%+v", original), fmt.Sprintf("%#v", original)} {
				if strings.Contains(text, original.verifier) || strings.Contains(text, original.state) || strings.Contains(text, original.config.ClientSecret) || strings.Contains(text, original.authorizationURL) {
					t.Fatal("pending handle formatting exposed secret")
				}
			}
			if cancelOriginal {
				p.Cancel(original)
			}
			u, _ := url.Parse(original.AuthorizationURL())
			callback := "https://client.example/callback?" + url.Values{"state": {u.Query().Get("state")}, "code": {"code"}}.Encode()
			_, err = p.Complete(ctx, &copied, callback)
			assertCode(t, err, auth.CodeInvalidConfiguration)
			if f.tokenCalls.Load() != 0 {
				t.Fatal("detached pending handle exchanged code")
			}
			if !cancelOriginal {
				if _, err = p.Complete(ctx, original, callback); err != nil {
					t.Fatal("copied handle consumed original")
				}
			}
		})
	}
}
func TestManagedCancelledSourcesReleasePendingCapacity(t *testing.T) {
	_, p, r := setup(t, "authorization_code_pkce")
	parent := budget(t)
	cancels := make([]context.CancelFunc, 0, 128)
	for i := range 128 {
		ctx, cancel := context.WithCancel(parent)
		cancels = append(cancels, cancel)
		request := r
		request.BackendID = fmt.Sprintf("backend-%d", i)
		prepared, err := p.Prepare(ctx, request)
		if err != nil || prepared.Login == nil {
			t.Fatalf("prepare %d: %v", i, err)
		}
	}
	for _, cancel := range cancels {
		cancel()
	}
	request := r
	request.BackendID = "replacement"
	prepared, err := p.Prepare(parent, request)
	if err != nil || prepared.Login == nil {
		t.Fatalf("cancelled operations exhausted capacity: %v", err)
	}
	p.mu.Lock()
	remaining := len(p.pending)
	p.mu.Unlock()
	if remaining != 1 {
		t.Fatal("cancelled login material retained")
	}
}
