package client

import (
	"fmt"
	"reflect"
	"strings"

	ahp "github.com/agenthooksprotocol/go-sdk"
)

// schemaSourceSlots walks Go's generated declared graph, not application JSON.
// Unknown variants, raw values, native data and all additional-property bags are
// opaque. Union/optional wrappers do not invent wire path segments.
func schemaSourceSlots(event map[string]any) (map[string]bool, error) {
	decoded, err := convertWire[ahp.Event](event)
	if err != nil {
		return nil, err
	}
	return schemaGraphSlots(decoded, ""), nil
}

func schemaGraphSlots(root any, rootPath string) map[string]bool {
	parts, _ := schemaGraphPaths(root, rootPath)
	return parts
}

func schemaGraphPaths(root any, rootPath string) (map[string]bool, map[string]bool) {
	opaque := map[string]bool{}
	found := map[string]bool{}
	partType := reflect.TypeFor[ahp.ContentItem]()
	textType := reflect.TypeFor[ahp.TextPart]()
	referenceType := reflect.TypeFor[ahp.ContentReference]()
	var visit func(reflect.Value, string)
	visit = func(value reflect.Value, path string) {
		if !value.IsValid() {
			return
		}
		if value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
			if value.IsNil() {
				return
			}
			visit(value.Elem(), path)
			return
		}
		typ := value.Type()
		if typ == partType {
			part := value.Interface().(ahp.ContentItem)
			if part.TextBodyPart.Present || part.TextGapPart.Present || part.TextMetadataPart.Present || part.TextOmittedPart.Present || part.AttachmentBodyPart.Present || part.AttachmentGapPart.Present || part.AttachmentMetadataPart.Present || part.AttachmentOmittedPart.Present {
				found[path] = true
			}
			return
		}
		if typ == textType {
			part := value.Interface().(ahp.TextPart)
			if part.TextBodyPart.Present || part.TextGapPart.Present || part.TextMetadataPart.Present || part.TextOmittedPart.Present {
				found[path] = true
			}
			return
		}
		if typ == referenceType {

			return
		}
		switch value.Kind() {
		case reflect.Slice, reflect.Array:
			// json.RawMessage/opaque bytes cannot contain schema-owned parts.
			if typ.Elem().Kind() == reflect.Uint8 {
				return
			}
			for i := 0; i < value.Len(); i++ {
				visit(value.Index(i), fmt.Sprintf("%s/%d", path, i))
			}
		case reflect.Struct:
			if strings.HasPrefix(typ.Name(), "Optional[") {
				if value.FieldByName("Present").Bool() {
					visit(value.FieldByName("Value"), path)
				}
				return
			}
			if strings.HasPrefix(typ.Name(), "Nullable[") {
				if value.FieldByName("Valid").Bool() {
					visit(value.FieldByName("Value"), path)
				}
				return
			}
			_, union := typ.FieldByName("Unknown")
			for i := 0; i < value.NumField(); i++ {
				field := typ.Field(i)
				if field.PkgPath != "" || field.Name == "AdditionalProperties" || field.Name == "Unknown" {
					continue
				}
				childPath := path
				if !union {
					name := field.Name
					switch name {
					case "ID":
						name = "id"
					case "MCP":
						name = "mcp"
					case "CWD":
						name = "cwd"
					case "JSONRPC":
						name = "jsonrpc"
					case "Meta":
						name = "_meta"
					default:
						name = strings.ToLower(name[:1]) + name[1:]
					}
					childPath += "/" + strings.ReplaceAll(strings.ReplaceAll(name, "~", "~0"), "/", "~1")
				}
				if !union && (field.Name == "Input" || field.Name == "Output" || field.Name == "Params" || field.Name == "Native" || field.Name == "Extensions") {
					opaque[childPath] = true
					continue
				}
				visit(value.Field(i), childPath)
			}
		}
	}
	visit(reflect.ValueOf(root), rootPath)
	return found, opaque
}
