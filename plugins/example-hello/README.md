# example-hello Plugin

A minimal example plugin demonstrating the 0xGen Plugin SDK usage patterns.

## Purpose

This plugin serves as a reference implementation for plugin developers, showcasing the simplest possible plugin that emits a finding. It's designed to help developers understand:

- Basic plugin structure and initialization
- The `OnStart` hook lifecycle
- How to emit findings using the Plugin SDK
- Manifest configuration requirements

## Features

- **Minimal Implementation**: Just 30 lines of code demonstrating core concepts
- **Single Finding Emission**: Emits one test finding on plugin startup
- **Trusted Plugin**: Runs with elevated privileges as a reference example
- **Capability Demonstration**: Shows `CAP_EMIT_FINDINGS` capability usage

## Usage

### Running the Example

The example-hello plugin is automatically loaded when 0xGen starts if enabled:

```bash
# Start 0xGen with example plugin
0xgenctl demo

# Or explicitly enable via config
0xgend start --enable-plugin example-hello
```

### Expected Output

When the plugin starts, it emits a single informational finding:

```json
{
  "type": "example.hello",
  "message": "Hello from example-hello!",
  "target": "example://hello",
  "severity": "info",
  "detected_at": "2025-11-20T10:30:45Z"
}
```

## Architecture

### Capabilities

- **`CAP_EMIT_FINDINGS`**: Permission to emit security findings to the 0xGen core

### Hooks

The plugin uses the `OnStart` lifecycle hook:

```go
hooks := pluginsdk.Hooks{
    OnStart: func(ctx *pluginsdk.Context) error {
        // Emit finding when plugin initializes
        return ctx.EmitFinding(pluginsdk.Finding{
            Type:       "example.hello",
            Message:    "Hello from example-hello!",
            Target:     "example://hello",
            Severity:   pluginsdk.SeverityInfo,
            DetectedAt: time.Now().UTC(),
        })
    },
}
```

### Plugin Lifecycle

1. **Initialization**: 0xGen loads the plugin binary
2. **Sandbox Setup**: Plugin runs in isolated environment (if not trusted)
3. **OnStart Hook**: Plugin's `OnStart` function is called
4. **Finding Emission**: Plugin emits the "Hello" finding
5. **Active State**: Plugin remains active but idle (no other hooks implemented)

## Configuration

### Manifest (`manifest.json`)

```json
{
  "name": "example-hello",
  "version": "0.1.0",
  "entry": "example-hello",
  "artifact": "plugins/example-hello/main.go",
  "trusted": true,
  "capabilities": ["CAP_EMIT_FINDINGS"]
}
```

**Key Fields**:
- `name`: Unique plugin identifier
- `version`: Semantic version (currently pre-release)
- `entry`: Binary name to execute
- `artifact`: Source file location
- `trusted`: `true` = runs without sandbox restrictions (use carefully!)
- `capabilities`: List of required permissions

## Development Guide

### Building from Source

```bash
# Navigate to plugin directory
cd plugins/example-hello

# Build the plugin binary
go build -o example-hello main.go

# Verify build
./example-hello
```

### Creating Your Own Plugin

Use this plugin as a template:

1. **Copy the structure**:
   ```bash
   cp -r plugins/example-hello plugins/my-plugin
   cd plugins/my-plugin
   ```

2. **Update manifest.json**:
   ```json
   {
     "name": "my-plugin",
     "version": "0.1.0",
     "entry": "my-plugin",
     "artifact": "plugins/my-plugin/main.go",
     "trusted": false,
     "capabilities": ["CAP_EMIT_FINDINGS"]
   }
   ```

3. **Modify main.go** to implement your detection logic

4. **Add additional hooks** as needed:
   - `OnHTTPRequest`: Intercept HTTP requests
   - `OnHTTPResponse`: Analyze HTTP responses
   - `OnFlowComplete`: Process complete request/response pairs
   - `OnStop`: Cleanup before shutdown

### Testing

```bash
# Run 0xGen with only your plugin
0xgend start --enable-plugin example-hello --disable-plugin hydra

# Check logs for the "Hello" finding
tail -f ~/.0xgen/logs/findings.jsonl | grep "example.hello"
```

## Security Considerations

### Trusted Plugin Flag

This plugin is marked as `trusted: true` in the manifest, which means:

- **No Sandbox**: Runs without cgroup/chroot restrictions
- **Full System Access**: Can access all files, network, processes
- **Production Risk**: Should NOT be enabled in production environments

**Best Practice**: Always set `trusted: false` for production plugins unless absolutely necessary.

### Capability Restrictions

Even though the plugin is trusted, it only requests `CAP_EMIT_FINDINGS`. This demonstrates the principle of least privilege:

```json
"capabilities": ["CAP_EMIT_FINDINGS"]
```

If you need additional capabilities, add them explicitly:
- `CAP_HTTP_PASSIVE`: Read HTTP traffic (passive analysis)
- `CAP_HTTP_ACTIVE`: Modify/inject HTTP traffic
- `CAP_FLOW_INSPECT`: Access complete request/response flows
- `CAP_AI_ANALYSIS`: Use AI evaluation services
- `CAP_NETWORK`: Make arbitrary network requests
- `CAP_FILE_READ`: Read files from disk
- `CAP_EXEC`: Execute external processes

## Common Use Cases

### 1. Plugin Development Learning

Use this plugin to understand the SDK without complexity:

```bash
# Study the code
cat plugins/example-hello/main.go

# Run and observe behavior
0xgenctl demo --verbose
```

### 2. Integration Testing

Verify the plugin system is working:

```bash
# Check plugin loads successfully
0xgend start --enable-plugin example-hello

# Verify finding is emitted
grep "example.hello" ~/.0xgen/logs/findings.jsonl
```

### 3. CI/CD Smoke Test

Include in automated tests:

```bash
#!/bin/bash
# test-plugin-system.sh

0xgend start --enable-plugin example-hello &
PID=$!
sleep 5

if grep -q "example.hello" ~/.0xgen/logs/findings.jsonl; then
    echo "✅ Plugin system working"
    kill $PID
    exit 0
else
    echo "❌ Plugin system failed"
    kill $PID
    exit 1
fi
```

## Troubleshooting

### Plugin Not Loading

**Symptom**: No "Hello" finding appears in logs

**Solutions**:
1. Check plugin is enabled:
   ```bash
   0xgend start --enable-plugin example-hello --log-level debug
   ```

2. Verify manifest.json syntax:
   ```bash
   jq . plugins/example-hello/manifest.json
   ```

3. Check binary exists and is executable:
   ```bash
   ls -lh plugins/example-hello/example-hello
   chmod +x plugins/example-hello/example-hello
   ```

### Finding Not Emitted

**Symptom**: Plugin loads but no finding in output

**Solutions**:
1. Check OnStart hook executed:
   ```bash
   tail -f ~/.0xgen/logs/0xgend.log | grep "example-hello"
   ```

2. Verify `CAP_EMIT_FINDINGS` capability is granted:
   ```bash
   # Should show capability in manifest
   jq .capabilities plugins/example-hello/manifest.json
   ```

### Permission Denied

**Symptom**: `permission denied` when running plugin

**Solutions**:
```bash
# Make binary executable
chmod +x plugins/example-hello/example-hello

# Or set trusted flag in manifest
jq '.trusted = true' plugins/example-hello/manifest.json > tmp.json
mv tmp.json plugins/example-hello/manifest.json
```

## Further Reading

- **Plugin SDK Documentation**: [docs/en/plugins/sdk-reference.md](../../docs/en/plugins/sdk-reference.md)
- **Plugin Security Guide**: [PLUGIN_GUIDE.md](../../PLUGIN_GUIDE.md)
- **Advanced Example**: See `plugins/hydra/` for a production-grade plugin
- **Plugin Developer Guide**: [docs/en/plugins/](../../docs/en/plugins/)

## License

This example plugin is released under the MIT License, same as 0xGen core.

## Version History

- **v0.1.0** (2025-11-20): Initial example plugin demonstrating basic SDK usage
