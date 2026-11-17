package oauth

import (
	"context"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/agenthooksprotocol/go-sdk/auth"
)

func TestPendingLoginFixedLifetime(t *testing.T) {
	for _, lifetime := range []time.Duration{0, 2 * time.Minute} {
		f, p, r := setup(t, "authorization_code_pkce")
		p.options.LoginLifetime = lifetime
		if lifetime == 0 {
			p.options.LoginLifetime = maxLoginLifetime
		}
		creator, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		before := time.Now()
		prepared, err := p.Prepare(creator, r)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		want := p.options.LoginLifetime
		if got := prepared.Login.Deadline().Sub(before); got < want || got > want+time.Minute {
			t.Fatalf("lifetime %v, want %v independent of the creating deadline", got, want)
		}
		// The creating prepare is cancelled; the stored login still completes.
		if _, err := p.Complete(budget(t), r, callback(prepared.Login, "code")); err != nil || f.tokenCalls.Load() != 1 {
			t.Fatalf("login did not survive its creator: %v", err)
		}
	}
	_, p, _ := setup(t, "authorization_code_pkce")
	options := p.options
	for _, invalid := range []time.Duration{-time.Second, maxLoginLifetime + time.Second} {
		options.LoginLifetime = invalid
		if _, err := New(options); err == nil {
			t.Fatalf("unbounded login lifetime %v accepted", invalid)
		}
	}
}

func TestPendingLoginCrossProcessCompletion(t *testing.T) {
	f, first, r := setup(t, "authorization_code_pkce")
	prepared, err := first.Prepare(budget(t), r)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(first.options)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := second.Complete(budget(t), r, callback(prepared.Login, "code"))
	if err != nil || credential.Token == "" {
		t.Fatalf("other process could not complete the stored login: %v", err)
	}
	_, err = first.Complete(budget(t), r, callback(prepared.Login, "code"))
	assertCode(t, err, auth.CodeInteractionRequired)
	if f.tokenCalls.Load() != 1 {
		t.Fatal("completed login exchanged twice")
	}
	if cached, err := first.Credential(budget(t), r); err != nil || cached.Token != credential.Token {
		t.Fatal("creating process did not see the completed grant")
	}
}

func TestPendingLoginReuse(t *testing.T) {
	_, p, r := setup(t, "authorization_code_pkce")
	long, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	first, err := p.Prepare(long, r)
	if err != nil {
		t.Fatal(err)
	}
	short, cancelShort := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShort()
	for _, required := range [][]string{nil, {"events"}} {
		again, err := p.Prepare(short, r, required...)
		if err != nil || again.Login.AuthorizationURL() != first.Login.AuthorizationURL() || !again.Login.Deadline().Equal(first.Login.Deadline()) {
			t.Fatalf("compatible prepare did not reuse the login or changed its lifetime: %v", err)
		}
	}
}

// Reuse ignores the new caller's ceiling; completion records scopes bounded
// by the creating ceiling, and each caller's ceiling filters them at use.
func TestPendingLoginReuseAcrossCeilings(t *testing.T) {
	f, p, r := setup(t, "authorization_code_pkce")
	original := p.options.SelectClient
	ceiling := []string{"events", "admin"}
	p.options.SelectClient = func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
		c, err := original(ctx, r, issuers, resource)
		c.AllowedScopes = ceiling
		return c, err
	}
	first, err := p.Prepare(budget(t), r, "admin")
	if err != nil {
		t.Fatal(err)
	}
	ceiling = []string{"events"}
	again, err := p.Prepare(budget(t), r)
	if err != nil || again.Login.AuthorizationURL() != first.Login.AuthorizationURL() {
		t.Fatalf("narrower caller did not reuse the login: %v", err)
	}
	f.mode.Store("admin-scope")
	credential, err := p.Complete(budget(t), r, callback(first.Login, "code"))
	if err != nil {
		t.Fatal(err)
	}
	record, _ := f.store.Load(budget(t), credential.Attempt.(attempted).key)
	if !sameScopes(record.Scopes, []string{"events", "admin"}) {
		t.Fatalf("completion not bounded by the creating ceiling: %v", record.Scopes)
	}
	_, err = p.Prepare(budget(t), r, "admin")
	assertCode(t, err, auth.CodeAccessDenied)
}

func TestPendingLoginSupersede(t *testing.T) {
	for _, change := range []string{"redirect", "partition", "scope"} {
		t.Run(change, func(t *testing.T) {
			f, p, r := setup(t, "authorization_code_pkce")
			original := p.options.SelectClient
			changed := false
			p.options.SelectClient = func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
				c, err := original(ctx, r, issuers, resource)
				c.AllowedScopes = []string{"events", "admin"}
				if change == "ceiling" && changed {
					c.AllowedScopes = []string{"events"}
				}
				if change == "redirect" && changed {
					c.RedirectURI = "https://client.example/other"
				}
				if change == "partition" && changed {
					c.GrantPartition = "shared"
				}
				return c, err
			}
			var required []string
			if change == "ceiling" {
				required = []string{"admin"}
			}
			old, err := p.Prepare(budget(t), r, required...)
			if err != nil {
				t.Fatal(err)
			}
			changed = true
			if change == "scope" {
				required = []string{"admin"}
			} else {
				required = nil
			}
			replacement, err := p.Prepare(budget(t), r, required...)
			if err != nil || replacement.Login.AuthorizationURL() == old.Login.AuthorizationURL() {
				t.Fatalf("incompatible prepare reused the login: %v", err)
			}
			_, err = p.Complete(budget(t), r, callback(old.Login, "old"))
			assertCode(t, err, auth.CodeInteractionRequired)
			if f.tokenCalls.Load() != 0 {
				t.Fatal("superseded callback exchanged a code")
			}
			redirect := "https://client.example/callback"
			if change == "redirect" {
				redirect = "https://client.example/other"
			}
			u, _ := url.Parse(callback(replacement.Login, "new"))
			if _, err := p.Complete(budget(t), r, redirect+"?"+u.RawQuery); err != nil {
				t.Fatalf("replacement login not completable: %v", err)
			}
		})
	}
}

func TestPendingLoginSupersedeScopeUnion(t *testing.T) {
	_, p, r := setup(t, "authorization_code_pkce")
	original := p.options.SelectClient
	p.options.SelectClient = func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
		c, err := original(ctx, r, issuers, resource)
		c.AllowedScopes = []string{"events", "admin", "write"}
		return c, err
	}
	admin, err := p.Prepare(budget(t), r, "admin")
	if err != nil {
		t.Fatal(err)
	}
	write, err := p.Prepare(budget(t), r, "write")
	if err != nil || write.Login.AuthorizationURL() == admin.Login.AuthorizationURL() {
		t.Fatalf("broader requirement did not supersede: %v", err)
	}
	if got := merge(loginScopes(write.Login)); !slices.Equal(got, []string{"admin", "events", "write"}) {
		t.Fatalf("superseding login scopes = %v, want the union", got)
	}
	// Alternating callers now converge on the union instead of looping.
	for _, required := range []string{"admin", "write", "admin"} {
		again, err := p.Prepare(budget(t), r, required)
		if err != nil || again.Login.AuthorizationURL() != write.Login.AuthorizationURL() {
			t.Fatalf("alternating requirement %s superseded the union: %v", required, err)
		}
	}
}

func TestPendingLoginEndStates(t *testing.T) {
	for _, end := range []string{"completion", "denial", "cancel", "expiry", "supersede"} {
		t.Run(end, func(t *testing.T) {
			f, p, r := setup(t, "authorization_code_pkce")
			if end == "expiry" {
				p.options.LoginLifetime = 50 * time.Millisecond
			}
			prepared, err := p.Prepare(budget(t), r)
			if err != nil {
				t.Fatal(err)
			}
			valid := callback(prepared.Login, "code")
			switch end {
			case "completion":
				if _, err := p.Complete(budget(t), r, valid); err != nil {
					t.Fatal(err)
				}
			case "denial":
				u, _ := url.Parse(valid)
				q := u.Query()
				q.Del("code")
				q.Set("error", "access_denied")
				_, err := p.Complete(budget(t), r, "https://client.example/callback?"+q.Encode())
				assertCode(t, err, auth.CodeAccessDenied)
			case "cancel":
				if err := p.Cancel(budget(t), r); err != nil {
					t.Fatal(err)
				}
			case "expiry":
				time.Sleep(100 * time.Millisecond)
			case "supersede":
				p.options.LoginLifetime = time.Minute
				original := p.options.SelectClient
				p.options.SelectClient = func(ctx context.Context, r auth.Request, issuers []string, resource string) (ClientConfig, error) {
					c, err := original(ctx, r, issuers, resource)
					c.RedirectURI = "https://client.example/other"
					return c, err
				}
				if _, err := p.Prepare(budget(t), r); err != nil {
					t.Fatal(err)
				}
			}
			calls := f.tokenCalls.Load()
			_, err = p.Complete(budget(t), r, valid)
			assertCode(t, err, auth.CodeInteractionRequired)
			if f.tokenCalls.Load() != calls {
				t.Fatal("ended login exchanged a code")
			}
		})
	}
	// Cancel never deletes a valid stored grant.
	f, p, r := setup(t, "authorization_code_pkce")
	allowAdmin(p)
	first := finishLogin(t, p, r)
	if prepared, err := p.Prepare(budget(t), r, "admin"); err != nil || prepared.Login == nil {
		t.Fatal(err)
	}
	if err := p.Cancel(budget(t), r); err != nil {
		t.Fatal(err)
	}
	record, _ := f.store.Load(budget(t), first.Attempt.(attempted).key)
	if record == nil || record.Pending != nil || record.AccessToken != first.Token {
		t.Fatal("cancel changed the stored grant")
	}
}
