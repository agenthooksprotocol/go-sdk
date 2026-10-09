// Command attachments sends file metadata to registered hooks and reads the
// invocation-owned body after shutdown. Usage: attachments registration.json report.pdf
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	ahp "github.com/agenthooksprotocol/go-sdk"
	"github.com/agenthooksprotocol/go-sdk/capability"
	"github.com/agenthooksprotocol/go-sdk/client"
	"github.com/agenthooksprotocol/go-sdk/content"
	"github.com/agenthooksprotocol/go-sdk/event"
)

func run(registrationPath, filePath string) error {
	data, err := os.ReadFile(registrationPath)
	if err != nil {
		return err
	}
	var registration ahp.Registration
	if err = json.Unmarshal(data, &registration); err != nil {
		return err
	}
	caps, err := capability.Intercept(capability.Deny())
	if err != nil {
		return err
	}
	hooks, err := client.New(registration, client.Options{Source: "urn:example:document-review", Events: map[string]client.EventCapabilities{"tool.before": caps}, MaxContentBytes: 8 << 20})
	if err != nil {
		return err
	}
	defer hooks.Close()
	// No file is opened for metadata-only selection. The factory owns its reader.
	attachment := content.NewLazyAttachment(func(ctx context.Context) (io.ReadCloser, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return os.Open(filePath)
	}, nil)
	item := &ahp.ContentItem{Metadata: ahp.Some(ahp.ContentItemMetadata{ID: "report", Kind: "file", MediaType: "application/pdf", Selection: "metadata"})}
	result, err := hooks.ToolBefore(context.Background(), event.ToolBeforeInput[map[string]string]{
		CallID: "review-1", Path: "execute", Name: "review_document", Origin: ahp.ExecutionEventToolOriginNative,
		Input: map[string]string{"path": filePath}, Items: ahp.Some([]*ahp.ContentItem{item}), ItemsSources: []*content.Source{attachment},
	})
	if result != nil {
		defer result.Close()
	}
	if err != nil {
		return err
	}
	if err = hooks.Close(); err != nil {
		return err
	}
	body, err := result.ReadContent(context.Background(), "/items/0")
	if err != nil {
		return err
	}
	fmt.Printf("Retained report: %d bytes\n", len(body))
	// This is content inspection, not permission to execute the native operation.
	return nil
}
func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: attachments registration.json report.pdf")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
