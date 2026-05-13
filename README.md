# Content Moderation MCP Server

AI-powered content moderation for your agents. Detect spam, toxicity, PII, profanity, and NSFW content via MCP protocol.

## Features

- **moderate_text** — Detect spam, toxicity, PII, profanity via rule-based regex patterns
- **moderate_image** — NSFW detection via pixel heuristics and image fingerprinting  
- **get_moderation_stats** — Check usage and tier status
- **Free tier**: 50 calls per restart
- **Pro tier**: $19/mo unlimited

## Quick Start

```bash
# Install
pip install mcp anyio

# Run (free tier)
python3 server.py

# Run (pro tier)
python3 server.py --pro-key PROL_AGENTPAY_DEMO
```

## Usage (Claude Desktop)

```json
{
  "mcpServers": {
    "content-moderation": {
      "command": "python3",
      "args": ["/path/to/server.py", "--pro-key", "PROL_AGENTPAY_DEMO"]
    }
  }
}
```

## License

MIT — AgentPay Labs
