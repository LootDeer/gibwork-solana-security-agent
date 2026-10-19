#!/usr/bin/env python3
"""
Gibwork Solana Security Agent
A standalone non-web CLI tool and Model Context Protocol (MCP) server
for auditing Solana SPL tokens, freeze/mint authority risks, and escrow safety.
"""

import sys
import json
import urllib.request
import urllib.error

SOLANA_RPC_URL = "https://api.mainnet-beta.solana.com"
DEXSCREENER_API_URL = "https://api.dexscreener.com/latest/dex/tokens/"

def query_solana_rpc(method, params):
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params
    }).encode("utf-8")
    req = urllib.request.Request(
        SOLANA_RPC_URL,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "GibworkSecurityAgent/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

def get_spl_mint_info(mint_address):
    res = query_solana_rpc("getAccountInfo", [
        mint_address,
        {"encoding": "jsonParsed"}
    ])
    if "error" in res or not res.get("result", {}).get("value"):
        return None
    data = res["result"]["value"].get("data", {})
    if not isinstance(data, dict) or data.get("program") != "spl-token":
        return None
    return data.get("parsed", {}).get("info", {})

def get_market_info(mint_address):
    req = urllib.request.Request(
        DEXSCREENER_API_URL + mint_address,
        headers={"User-Agent": "GibworkSecurityAgent/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            pairs = data.get("pairs") or []
            sol_pairs = [p for p in pairs if p.get("chainId") == "solana"]
            if not sol_pairs:
                return {"liquidity_usd": 0, "volume_24h": 0, "pair_address": None}
            best = max(sol_pairs, key=lambda x: (x.get("liquidity", {}).get("usd") or 0))
            return {
                "liquidity_usd": best.get("liquidity", {}).get("usd", 0),
                "volume_24h": best.get("volume", {}).get("h24", 0),
                "pair_address": best.get("pairAddress")
            }
    except Exception:
        return {"liquidity_usd": 0, "volume_24h": 0, "pair_address": None}

def analyze_token_risk(mint_address):
    mint_info = get_spl_mint_info(mint_address)
    if not mint_info:
        return {"error": f"Invalid SPL token address or not found on Solana mainnet: {mint_address}"}
    
    market = get_market_info(mint_address)
    mint_auth = mint_info.get("mintAuthority")
    freeze_auth = mint_info.get("freezeAuthority")
    decimals = mint_info.get("decimals", 0)
    supply_raw = int(mint_info.get("supply", 0))
    supply = supply_raw / (10 ** decimals) if decimals > 0 else supply_raw

    risk_factors = []
    risk_score = 10

    if freeze_auth is not None:
        risk_score += 60
        risk_factors.append(f"CRITICAL: freezeAuthority is active ({freeze_auth}). Token accounts can be frozen (honeypot risk).")
    else:
        risk_factors.append("VERIFIED: freezeAuthority is revoked (immutable account states).")

    if mint_auth is not None:
        risk_score += 25
        risk_factors.append(f"HIGH: mintAuthority is active ({mint_auth}). Creator can arbitrarily inflate supply.")
    else:
        risk_factors.append("VERIFIED: mintAuthority is revoked (fixed supply cap).")

    liq = market.get("liquidity_usd", 0)
    if liq < 5000:
        risk_score += 15
        risk_factors.append(f"LOW LIQUIDITY: Under $5,000 USD (${liq:,.2f}). High slippage and price vulnerability.")

    risk_score = min(100, risk_score)
    if risk_score >= 70:
        classification = "CRITICAL RISK"
    elif risk_score >= 40:
        classification = "HIGH RISK"
    elif risk_score >= 25:
        classification = "MODERATE CAUTION"
    else:
        classification = "LOW RISK"

    return {
        "mint": mint_address,
        "decimals": decimals,
        "supply": supply,
        "freezeAuthority": freeze_auth,
        "mintAuthority": mint_auth,
        "liquidity_usd": liq,
        "risk_score": risk_score,
        "classification": classification,
        "risk_factors": risk_factors
    }

def validate_bounty_token_escrow(mint_address, max_allowed_risk=30):
    report = analyze_token_risk(mint_address)
    if "error" in report:
        return {"approved": False, "reason": report["error"]}
    
    score = report.get("risk_score", 100)
    approved = score <= max_allowed_risk
    return {
        "approved": approved,
        "mint": mint_address,
        "risk_score": score,
        "classification": report.get("classification"),
        "reason": "Escrow safety requirements met." if approved else f"Risk score {score} exceeds max threshold {max_allowed_risk}."
    }

# MCP Server Implementation
def handle_mcp_request(line):
    try:
        req = json.loads(line)
    except Exception:
        return
    msg_id = req.get("id")
    method = req.get("method")
    params = req.get("params", {})

    if method == "initialize":
        response = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "gibwork-solana-security-agent", "version": "1.0.0"}
            }
        }
    elif method == "tools/list":
        response = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": [
                    {
                        "name": "analyze_solana_token_risk",
                        "description": "Performs comprehensive on-chain safety verification of Solana SPL tokens (freeze/mint authorities, liquidity).",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"mint_address": {"type": "string", "description": "Solana SPL Token mint address"}},
                            "required": ["mint_address"]
                        }
                    },
                    {
                        "name": "validate_bounty_token_escrow",
                        "description": "Validates whether a token is safe to be accepted into Gibwork bounty escrow.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "mint_address": {"type": "string", "description": "Solana SPL Token mint address"},
                                "max_allowed_risk": {"type": "integer", "description": "Maximum risk threshold (0-100)", "default": 30}
                            },
                            "required": ["mint_address"]
                        }
                    }
                ]
            }
        }
    elif method == "tools/call":
        tool_name = params.get("name")
        args = params.get("arguments", {})
        if tool_name == "analyze_solana_token_risk":
            res = analyze_token_risk(args.get("mint_address", ""))
        elif tool_name =("validate_bounty_token_escrow"):
            res = validate_bounty_token_escrow(args.get("mint_address", ""), args.get("max_allowed_risk", 30))
        else:
            res = {"error": f"Unknown tool: {tool_name}"}
        
        response = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "content": [{"type": "text", "text": json.dumps(res, indent=2)}]
            }
        }
    else:
        response = {"jsonrpc": "2.0", "id": msg_id, "result": {}}

    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()

def run_mcp_server():
    for line in sys.stdin:
        line = line.strip()
        if line:
            handle_mcp_request(line)

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--mcp":
        run_mcp_server()
        return

    if len(sys.argv) > 1 and sys.argv[1] == "--mint":
        mint = sys.argv[2]
        res = analyze_token_risk(mint)
        if "--json" in sys.argv:
            print(json.dumps(res, indent=2))
        else:
            print(f"=== Solana Token Risk Report: {mint} ===")
            print(f"Classification: {res.get('classification')}")
            print(f"Risk Score:     {res.get('risk_score')}/100")
            print(f"Freeze Auth:    {res.get('freezeAuthority')}")
            print(f"Mint Auth:      {res.get('mintAuthority')}")
            print(f"Liquidity USD:  ${res.get('liquidity_usd', 0):,.2f}")
            print("\nRisk Factors:")
            for rf in res.get("risk_factors", []):
                print(f" - {rf}")
        return

    print("Usage:")
    print("  CLI mode: python3 gibwork_security_agent.py --mint <MINT_ADDRESS> [--json]")
    print("  MCP mode: python3 gibwork_security_agent.py --mcp")

if __name__ == "__main__":
    main()
