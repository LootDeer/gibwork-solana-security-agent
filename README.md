# Gibwork Solana Security Agent 🛡️

A non-web, developer-focused CLI tool and **Model Context Protocol (MCP)** server built for auditing Solana SPL tokens, freeze/mint authority risks, and bounty escrow safety.

Engineered for the **Gibwork Developer Hackathon Bounty** (non-web CLI / SDK / MCP tools for developers and autonomous AI agents).

---

## Key Features

- **Pure Python & Zero Dependencies**: Runs directly on Python 3 standard library (`urllib`, `json`). Zero `pip install` required.
- **Direct On-Chain Verification**: Communicates directly with the native Solana JSON-RPC (`https://api.mainnet-beta.solana.com`) to inspect raw SPL Token mint account structures without relying on third-party API keys.
- **Honeypot & Risk Detection**:
  - `freezeAuthority`: Detects if creator can freeze token accounts (critical honeypot indicator).
  - `mintAuthority`: Checks whether total supply can be arbitrarily inflated by creator.
  - `liquidity & volume`: Validates live DEX pool depth via DexScreener API.
- **Model Context Protocol (MCP) Support**: Implements JSON-RPC 2.0 stdio server, allowing autonomous AI agents (Claude Desktop, Cursor, Maia) to dynamically invoke on-chain audits.
- **Gibwork Escrow Integration**: Special tool `validate_bounty_token_escrow` prevents funding bounties or releasing payouts with unsafe tokens.

---

## CLI Usage

### Basic CLI Audit
```bash
python3 gibwork_security_agent.py --mint DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263
```

### JSON Output
```bash
python3 gibwork_security_agent.py --mint DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263 --json
```

---

## MCP Server Integration

To connect this agent with Claude Desktop or Cursor, add this configuration to your `mcpServers` config file:

```json
{
  "mcpServers": {
    "solana-security": {
      "command": "python3",
      "args": ["/path/to/gibwork_security_agent.py", "--mcp"]
    }
  }
}
```

### Available Tools via MCP

1. `analyze_solana_token_risk`: Audits mint authority, freeze authority, supply, and DEX liquidity depth.
2. `validate_bounty_token_escrow`: Checks whether a token meets strict safety thresholds before accepting it into a bounty reward escrow.

---

## License
MIT
