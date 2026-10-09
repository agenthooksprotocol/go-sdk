package client

import (
	"context"
	"io"
	"strings"
	"testing"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/content"
	"github.com/agenthooksprotocol/go-sdk/event"
)

func TestOwnedAttachmentsTypedLifetime(t *testing.T) {
	for _, mode := range []string{"metadata", "no-match"} {
		t.Run(mode, func(t *testing.T) {
			c, _ := testClient(t, "fail-open")
			c.backends[0].subscriptions[0]["content"] = map[string]any{"default": "metadata"}
			if mode == "no-match" {
				c.backends[0].subscriptions = nil
			}
			opens, closes := 0, 0
			a := content.NewLazyAttachment(func(context.Context) (io.ReadCloser, error) {
				opens++
				return io.NopCloser(strings.NewReader("file bytes")), nil
			}, func() error { closes++; return nil })
			var item ahp.ContentItem
			if err := item.UnmarshalJSON([]byte(`{"id":"report","kind":"file","mediaType":"application/octet-stream","selection":"metadata"}`)); err != nil {
				t.Fatal(err)
			}
			result, err := c.ToolBefore(context.Background(), event.ToolBeforeInput[map[string]any]{
				CallID: "call-1", Path: "execute", Name: "read_file", Origin: ahp.ExecutionEventToolOriginNative,
				Input: map[string]any{}, Items: ahp.Optional[[]*ahp.ContentItem]{Present: true, Value: []*ahp.ContentItem{&item}},
				ItemsSources: []*content.Source{a},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer result.Close()
			if opens != 0 || closes != 0 {
				t.Fatalf("premature materialization/close: %d/%d", opens, closes)
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				raw, err := result.ReadContent(context.Background(), "/items/0")
				if err != nil || string(raw) != "file bytes" {
					t.Fatalf("read %q: %v", raw, err)
				}
				raw[0] = 'X'
			}
			if opens != 1 || closes != 1 {
				t.Fatalf("open/cleanup: %d/%d", opens, closes)
			}
			if err := result.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := result.ReadContent(context.Background(), "/items/0"); err == nil {
				t.Fatal("read after close")
			}
		})
	}
}

func TestOwnedAttachmentUnopenedCleanupAndReuse(t *testing.T) {
	c, _ := testClient(t, "fail-open")
	c.backends[0].subscriptions = nil
	opens, closes := 0, 0
	a := content.NewLazyAttachment(func(context.Context) (io.ReadCloser, error) {
		opens++
		return io.NopCloser(strings.NewReader("abc")), nil
	}, func() error { closes++; return nil })
	input := testInput()
	item := contentTestItem(nil)
	delete(item, "body")
	item["selection"] = "metadata"
	input["items"] = []any{item}
	result, err := c.Dispatch(context.Background(), "tool.before", input, WithContentSource("/items/0", a))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Dispatch(context.Background(), "tool.before", input, WithContentSource("/items/0", a)); err == nil {
		t.Fatal("reuse accepted")
	}
	if closes != 0 {
		t.Fatal("reuse retired first result")
	}
	_ = result.Close()
	_ = result.Close()
	if opens != 0 || closes != 1 {
		t.Fatalf("open/cleanup %d/%d", opens, closes)
	}
}

func TestOwnedAttachmentCopiesAndLimits(t *testing.T) {
	for _, limit := range []int64{2, 3} {
		c, _ := testClient(t, "fail-open")
		c.opts.MaxContentBytes = limit
		c.backends[0].subscriptions = nil
		raw := []byte("abc")
		a := content.NewAttachment(raw)
		raw[0] = 'X'
		input := testInput()
		item := contentTestItem(nil)
		delete(item, "body")
		item["selection"] = "metadata"
		input["items"] = []any{item, item}
		result, err := c.Dispatch(context.Background(), "tool.before", input, WithContentSource("/items/0", a), WithContentSource("/items/1", a))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"/items/0", "/items/1"} {
			b, err := result.ReadContent(context.Background(), path)
			if limit == 2 {
				if err == nil {
					t.Fatal("limit ignored")
				}
			} else {
				if err != nil || string(b) != "abc" {
					t.Fatalf("%q %v", b, err)
				}
				b[0] = 'Y'
			}
		}
		_ = result.Close()
	}
}

func TestOwnedAttachmentAdmissionFailure(t *testing.T) {
	c, _ := testClient(t, "fail-open")
	opens, closes := 0, 0
	a := content.NewLazyAttachment(func(context.Context) (io.ReadCloser, error) { opens++; return nil, nil }, func() error { closes++; return nil })
	if _, err := c.Dispatch(context.Background(), "tool.before", nil, WithContentSource("/items/0", a)); err == nil {
		t.Fatal("bad input admitted")
	}
	if opens != 0 || closes != 1 {
		t.Fatal(opens, closes)
	}
}

func TestOwnedAttachmentAggregateLimit(t *testing.T) {
	c, _ := testClient(t, "fail-open")
	c.opts.MaxContentBytes = 5
	c.backends[0].subscriptions = nil
	a, b := content.NewAttachment([]byte("abc")), content.NewAttachment([]byte("def"))
	input := testInput()
	item := contentTestItem(nil)
	delete(item, "body")
	item["selection"] = "metadata"
	input["items"] = []any{item, item}
	result, err := c.Dispatch(context.Background(), "tool.before", input, WithContentSource("/items/0", a), WithContentSource("/items/1", b))
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if _, err := result.ReadContent(context.Background(), "/items/0"); err != nil {
		t.Fatal(err)
	}
	if _, err := result.ReadContent(context.Background(), "/items/1"); err == nil {
		t.Fatal("aggregate budget ignored")
	}
}
