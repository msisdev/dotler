# AI Support

Dotler includes built-in tools for AI coding agents:

- **`dotler.toml` & `dotler init` Hints**: `dotler init` outputs an onboarding hint and places a top-of-file comment in `dotler.toml` instructing AI agents to run `dotler ai` before editing configuration or syncing files.
- **`dotler ai` & `--json`**: `dotler ai` prints a one-shot environment briefing (full `dotler.toml` schema, active OS/device keys, registered repositories, and keyring status without exposing secrets). Every command supports `--json` for structured output.
- **`dotler mcp`**: Runs a built-in Model Context Protocol (`MCP`) server over `stdio`.

## MCP Server Configuration

Add `dotler mcp` to your AI client configuration:

```json
{
  "mcpServers": {
    "dotler": {
      "command": "dotler",
      "args": ["mcp"]
    }
  }
}
```
