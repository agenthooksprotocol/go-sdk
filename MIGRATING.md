# Migrating

## 0.4 → 0.5

Version 0.5.0 removes the draft compatibility APIs. In their place it adds
typed host declarations, separate handlers for each event, and one generated
event-name type. The wire protocol does not change. Only Go source has to
change. The sections below list each removed or renamed API with its
replacement.

### Host capability declarations (`capability`, `client.Options`)

`client.Options.Events` used to be a `map[string]client.EventCapabilities`
built with `capability.Intercept(grants...)`. It is now a `capability.Host`
struct with one typed field per event. You can only set the facilities that
the catalogue supports for that event, and declarations no longer return
errors.

Before (0.4):

```go
toolBefore, err := capability.Intercept(
    capability.Deny(),
    capability.ModifyInput(capability.Replace, capability.Merge),
    capability.FlowStop(),
    capability.InjectContextAppend(capability.Now, capability.NextTurn),
)
if err != nil { return nil, err }
hooks, err := client.New(reg, client.Options{
    Source: "urn:example:host",
    Events: map[string]client.EventCapabilities{
        "tool.before": toolBefore,
        "session.end": capability.Observe(),
    },
})
```

After (0.5):

```go
hooks, err := client.New(reg, client.Options{
    Source: "urn:example:host",
    Events: capability.Host{
        ToolBefore: capability.ToolBefore{
            Deny:          true,
            ModifyInput:   capability.ReplaceAndMerge(),
            Flow:          capability.Stop(),
            InjectContext: capability.InjectNow().WithNextTurn(),
            Observe:       true, // capability.Intercept advertised both modes
        },
        SessionEnd: capability.Observe{},
    },
})
```

`capability.Intercept` advertised both the intercept and observe modes. A 0.5
declaration enables interception when any facility is set. Observation is
enabled only when you also set `Observe: true`. Keep `Observe: true` if your
host still delivers observations for that event.

| 0.4 | 0.5 |
| --- | --- |
| `client.EventCapabilities`, `capability.Event` | The event's field on `capability.Host`, for example `capability.ToolBefore{...}` |
| `capability.Intercept(grants...)` | Facility fields on the event declaration, plus `Observe: true` |
| `capability.Observe()` | `capability.Observe{}` |
| `capability.Allow()`, `Ask()`, `Deny()`, `Message()` | `Allow`, `Ask`, `Deny`, `Message: true` |
| `capability.Return()` | `ReturnResult: true` |
| `capability.Modify<Target>(capability.Replace)` | `Modify<Target>: capability.Replace()` |
| `capability.Modify<Target>(capability.Merge)` | `Modify<Target>: capability.Merge()` |
| `capability.Modify<Target>(capability.Replace, capability.Merge)` | `Modify<Target>: capability.ReplaceAndMerge()` |
| `capability.Replace`, `capability.Merge` (constants) | `capability.Replace()`, `capability.Merge()` (functions) |
| `capability.FlowStop()` | `Flow: capability.Stop()` |
| `capability.FlowContinue(remaining, count)` | `Flow: capability.Continue(remaining, count)` or `capability.ContinueAndStop(remaining, count)`. The counters are now `uint64` |
| `capability.InjectContextAppend(capability.Now)` | `InjectContext: capability.InjectNow()` |
| `capability.InjectContextAppend(capability.NextTurn)` | `InjectContext: capability.InjectNextTurn()` |
| Both delivery timings | `capability.InjectNow().WithNextTurn()` |
| `capability.ElicitationForm()`, `ElicitationURL()` | `ElicitationForm: true`, `ElicitationURL: true` |
| `capability.Mode`, `InterceptMode`, `ObserveMode`, `client.Mode`, `client.Intercept`, `client.Observe` | Removed. Modes come from the declaration |
| `capability.Grant`, `capability.DeliverAt`, `capability.ModifyOperation`, `capability.Now`, `capability.NextTurn` | Removed. Use the constructors above |
| `capability.New`, `capability.New<Event>`, `capability.<Event>Option`, `capability.With<Event>*` | `capability.Host`. Use `Host.Wire()` when manifest tooling needs the rendered wire declarations |
| `capability.NewStaticCapabilityManifest`, `client.Options.Manifest` | `client.Options.Events` together with `client.Options.Metadata` |

`client.Options.Manifest` used to take a complete static manifest in place of
`Events`. Events and grants now always come from `Options.Events`. Only
metadata that is not about events goes in `Options.Metadata`:

```go
client.Options{
    Source: "urn:example:host",
    Events: capability.Host{SessionStart: capability.Observe{}},
    Metadata: &client.ManifestMetadata{
        ContentCategories: ahp.Some([]string{"text"}),
    },
}
```

`client.WithCapabilities` still takes an `ahp.Capabilities` wire value, and it
still can only narrow the manifest.

### Server handlers (`server`)

`server.Handlers.Intercept` and `server.Handlers.Observe` used to be single
callbacks that received every event as a raw union. They are now handler
structs with one field per event. Each callback receives the exact event and
its capability grants, and intercept callbacks return a reply type for that
event. The engine fills in the protocol version and request correlation.

Before (0.4):

```go
handler, err := server.NewHandler(server.Handlers{
    Intercept: func(ctx context.Context, request ahp.InterceptRequest) (ahp.InterceptResponseResult, error) {
        return ahp.InterceptResponseResult{}, nil
    },
    Observe: func(ctx context.Context, notification ahp.ObserveNotification) error {
        return nil
    },
}, server.Options{})
```

After (0.5):

```go
handler, err := server.NewHandler(server.Handlers{
    Intercept: server.InterceptHandlers{
        ToolBefore: func(ctx context.Context,
            request server.InterceptContext[ahp.ToolBeforeEvent, ahp.ToolBeforeCapabilities],
        ) (server.ToolBeforeReply, error) {
            return server.ToolBeforeReply{}, nil // zero reply is a no-op
        },
    },
    Observe: server.ObserveHandlers{
        SessionEnd: func(ctx context.Context,
            notification server.ObserveContext[ahp.SessionEndEvent],
        ) error {
            return nil
        },
    },
}, server.Options{})
```

In an intercept context, `request.Event` is the typed event and
`request.Capabilities` are its grants. `request.State`, `request.Extensions`,
`request.AdditionalProperties` and `request.EnvelopeExtras` carry the remaining
request data. Reply `Effects` use the event-specific `ahp.<Event>Effect` unions.
Use `server.WithToolBeforeArguments(codec, callback)` to decode tool arguments
into a type you declare. If an event's callback is nil, that event is rejected.

### Event names (`event`, root `ahp`)

The event constants are now the generated defined type `event.Type`, not
untyped strings. This applies to `event.ToolBefore`, `event.SessionEnd` and
the other constants. APIs that take an event name now take `event.Type`.

| 0.4 | 0.5 |
| --- | --- |
| `hooks.Dispatch(ctx, "tool.before", input)` | `hooks.Dispatch(ctx, event.ToolBefore, input)` |
| `ahp.ResponseForRequest(eventType string, b)` | `event.ResponseForRequest(event.ToolBefore, b)` |
| `ahp.StageResponseForRequest(eventType string, b, validate)` | `event.StageResponseForRequest(event.ToolBefore, b, validate)` |
| `client.CapabilityAdmissionError.Event` (`string`) | `event.Type` |
| Passing `event.ToolBefore` where a `string` is expected | `string(event.ToolBefore)` |

Wire registration selectors are still strings and still accept exact names,
`*` and prefixes. `hooks.Subscribes(event.ToolBefore)` is new. It reports
static subscription interest before you prepare expensive input.

### Boundary results (`client.Result`)

| 0.4 | 0.5 |
| --- | --- |
| `Result.SettledEvent` | `Result.Event` (`*ahp.Event`) |
| `Result.Event`, `Result.EffectiveInput` (`json.RawMessage`) | `json.Marshal(result.Event)`, or read the typed boundary variant of `Result.Event` |
| `Result.EffectiveValue(target)` | Read the typed variant of `Result.Event`. Use `Result.Content`/`ReadContent` for attachment bytes |
| `Result.SettledCandidate`, `client.SettledCandidate` | `Result.Candidate`, `client.Candidate` |
| `Result.AcceptedResponse` | The last element of `Result.AcceptedResponses` |
| `Result.Response` (composed effect aggregate) | `Result.AcceptedResponses`, plus the settled fields below |
| `Result.State` | `Result.Permission`, `Flow`, `Candidate`, `Instructions`, `Injections`, `StateExtras` |
| `Result.Errors` | `Result.Diagnostics`, which already contained every interception failure |
| `Result.Observations`, `client.Observations` | Removed. Boundary calls finish observations before they return, and failures appear in `Result.Diagnostics` |

```go
_ = result.Event     // was SettledEvent
_ = result.Candidate // was SettledCandidate
var last ahp.ContextualResponse
if n := len(result.AcceptedResponses); n > 0 {
    last = result.AcceptedResponses[n-1] // was AcceptedResponse
}
raw, err := json.Marshal(result.Event) // was EffectiveInput
```

### Other removed aliases (`client`, `content`)

| 0.4 | 0.5 |
| --- | --- |
| `client.Client` | `client.Hooks` |
| `client.ContentSource`, `client.NewContentSource(r)` | `content.Source`, `content.NewSource(r)` |
| `content.Attachment` | `content.Source` (`content.NewAttachment` now returns `*content.Source`) |
| `client.DeliveryCode`, `client.Delivery*` constants | `diagnostic.Code` and `diagnostic.ProtocolRejection`, `RemoteRpc`, `Transport`, `Cancelled`, `DeadlineExceeded`, `Preparation`, `Capacity` |
| `client.EventTransportResolver`, `Options.EventTransportResolver` | `Options.AuthProvider` (`auth.Provider`), or a configured `Options.EventClient` |
| `client.ContentAuthorization.Subscription` (`map[string]any`) | `ahp.BackendSubscriptionsItem` |
| `client.ContentAuthorization.Item` (`map[string]any`) | `client.ContentDescriptor`, a description of the content before it is disclosed, without its text, body or gap |
