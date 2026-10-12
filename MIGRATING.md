# Migrating

## 0.5 → next (unreleased)

### Stdio backend environment

Stdio backends no longer inherit the full host environment. A child process
now gets a minimal base (`PATH`, `HOME`, locale, temp directories and similar)
plus the registration's stdio `env` entries. If a backend needs other host
variables, list them in its registration:

```json
{"type": "stdio", "command": "backend", "lifecycle": "persistent",
 "env": {"BACKEND_CONFIG": "/etc/backend.toml"}}
```

To keep the old behaviour while you migrate, set
`client.Options{InheritEnvironment: true}`.

### Observation-only capability declarations

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
