# Migrating

## 0.5 → next (unreleased)

The shared `capability.Observe` declaration is removed. Every event now has
its own declaration type, so an observation-only event uses that event's
declaration with only `Observe: true` set.

Before (0.5):

```go
capability.Host{
    SessionEnd: capability.Observe{},
    ToolBefore: capability.Observe{},
}
```

After:

```go
capability.Host{
    SessionEnd: capability.SessionEnd{Observe: true},
    ToolBefore: capability.ToolBefore{Observe: true},
}
```

Events that have only observation support (for example `SessionEnd`,
`TurnEnd`, `FileChanged`) now have declaration types whose only field is
`Observe`. The emitted manifest does not change.
