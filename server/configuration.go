package server

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	ahp "github.com/agenthooksprotocol/go-sdk"
	canonicalpkg "github.com/agenthooksprotocol/go-sdk/internal/canonical"
)

// snapshotConfiguration detaches caller-owned slices and maps before serving.
// RawMessage preserves exact numeric settings and unknown extension fields.
func snapshotConfiguration(configuration *ahp.Configuration) (json.RawMessage, error) {
	if configuration == nil {
		return nil, nil
	}
	encoded, err := json.Marshal(configuration)
	if err != nil || canonicalpkg.Validate("configuration", encoded) != nil {
		return nil, errors.New("server: invalid configuration")
	}
	return json.RawMessage(encoded), nil
}

// ErrConfigurationUnavailable is the redacted diagnostic for failed dynamic
// configuration resolution. It never wraps application errors or panic values.
var ErrConfigurationUnavailable = errors.New("server: configuration unavailable")

type configurationResolver func(context.Context) (json.RawMessage, error)

func prepareConfiguration(source ahp.ConfigurationSource) (configurationResolver, error) {
	if source == nil {
		return nil, nil
	}
	value := reflect.ValueOf(source)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return nil, nil
		}
	}
	if static, ok := source.(*ahp.Configuration); ok {
		snapshot, err := snapshotConfiguration(static)
		if err != nil {
			return nil, err
		}
		return func(ctx context.Context) (json.RawMessage, error) {
			if ctx.Err() != nil {
				return nil, ErrConfigurationUnavailable
			}
			return snapshot, nil
		}, nil
	}
	return func(ctx context.Context) (snapshot json.RawMessage, err error) {
		defer func() {
			if recover() != nil {
				snapshot, err = nil, ErrConfigurationUnavailable
			}
		}()
		if ctx.Err() != nil {
			return nil, ErrConfigurationUnavailable
		}
		configuration, err := source.ResolveConfiguration(ctx)
		if err != nil || configuration == nil || ctx.Err() != nil {
			return nil, ErrConfigurationUnavailable
		}
		snapshot, err = snapshotConfiguration(configuration)
		if err != nil || ctx.Err() != nil {
			return nil, ErrConfigurationUnavailable
		}
		return snapshot, nil
	}, nil
}
