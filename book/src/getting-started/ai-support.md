# AI Support

Dotler includes built-in tools for AI coding agents:

- **`SKILL.md`**: Generated in your repository by `dotler init` (existing `SKILL.md` files are preserved). Gives AI agents the exact `dotler.toml` syntax and safe workflow rules.
- **`dotler ai` & `--json`**: `dotler ai` prints a one-shot environment briefing (active OS keys, registered repositories, and keyring status without exposing secrets). Every command supports `--json` for structured output.
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
