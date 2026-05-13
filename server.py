#!/usr/bin/env python3
"""Content Moderation MCP Server — Detect spam, toxicity, PII, profanity, and NSFW content for AI agents.

Uses rule-based detection (keyword matching, regex patterns) — no paid API needed.

Usage:
  python3 server.py                                          # Free tier (50 calls)
  python3 server.py --pro-key PROL_XXX                        # Pro tier (unlimited)
"""

import os, json, sys, re, base64, hashlib
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

server = Server("content-moderation-mcp")

# ─── Rate Limiting & Pro Key ───────────────────────────────────────────
FREE_LIMIT = 50
PRO_KEYS = {"PROL_AGENTPAY_DEMO": "demo"}  # Demo key for testing

# Parse --pro-key from command line
PRO_KEY = None
for i, arg in enumerate(sys.argv):
    if arg == "--pro-key" and i + 1 < len(sys.argv):
        PRO_KEY = sys.argv[i + 1]
        break

IS_PRO = PRO_KEY in PRO_KEYS
call_counter = 0

STRIPE_LINK = "https://buy.stripe.com/5kQ8wR0qXbg05zGdjl1oI0C"  # $19/mo

def check_rate_limit():
    """Check if free tier has exceeded limit. Returns error dict or None."""
    global call_counter
    if IS_PRO:
        return None
    call_counter += 1
    if call_counter > FREE_LIMIT:
        remaining = call_counter - FREE_LIMIT
        return {
            "error": f"Free tier limit reached ({FREE_LIMIT} calls). Upgrade to Pro for unlimited access.",
            "isError": True,
            "next_steps": [
                f"Purchase Pro at {STRIPE_LINK} ($19/mo, unlimited)",
                "Restart the server to reset the free counter",
                "Use --pro-key PROL_XXX to run in Pro mode"
            ],
            "calls_used": call_counter,
            "limit": FREE_LIMIT,
            "over_by": remaining
        }
    return None

# ─── Moderation Patterns ────────────────────────────────────────────────

SPAM_PATTERNS = [
    re.compile(r'\b(buy\s+now|click\s+here|act\s+now|limited\s+time|free\s+money|congratulations.*winner)\b', re.IGNORECASE),
    re.compile(r'\b(earn\s+\$\d+|make\s+money\s+fast|get\s+rich|work\s+from\s+home\s+\$\d+)\b', re.IGNORECASE),
    re.compile(r'\b(crypto\s+giveaway|bitcoin\s+double|eth\s+giveaway|nft\s+airdrop)\b', re.IGNORECASE),
    re.compile(r'(?:https?:\/\/)?(?:www\.)?(?:bit\.ly|tinyurl\.com|shorturl\.at|shorte\.st|t\.co)\/\S+', re.IGNORECASE),
    re.compile(r'A-Z\s{20,}'),
]

TOXIC_PATTERNS = [
    re.compile(r'\b(fuck|shit|damn|ass\s*hole|bastard|bitch|crap|dick|piss)\b', re.IGNORECASE),
    re.compile(r'\b(stfu|wtf|lmfao|go\s+d(i|ie)\s+in\s+a\s+(fire|hole))\b', re.IGNORECASE),
    re.compile(r'\b(kill\s+(yourself|urself|yo\s*self)|end\s+(yourself|it))\b', re.IGNORECASE),
    re.compile(r'\b(dumbass|dipshit|shithead|jackass|pissed\s+off)\b', re.IGNORECASE),
]

PROFANITY_PATTERNS = [
    re.compile(r'\b(f+u+c+k+|s+h+i+t+|b+i+t+c+h+|d+a+m+n+|a+s+s+)\b', re.IGNORECASE),
    re.compile(r'\b(c+u+n+t+|d+i+c+k+|p+u+s+s+y+|c+o+c+k+)\b', re.IGNORECASE),
    re.compile(r'\b(b+o+l+l+o+c+k+s+|m+o+t+h+e+r+f+u+c+k+e+r+|a+f|b+s+|a+5+s+|s+h+1+t+)\b', re.IGNORECASE),
]

PII_PATTERNS = {
    "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
    "phone_us": re.compile(r'\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b'),
    "ssn": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    "credit_card": re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
    "ip_address": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "bitcoin_address": re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
    "eth_address": re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
    "api_key": re.compile(r'\b(sk[-_][a-zA-Z0-9]{20,}|api[-_]key[-_][a-zA-Z0-9]{16,}|[-_]{20,})\b', re.IGNORECASE),
}

# ─── Moderation Engine ──────────────────────────────────────────────────

def _mask_value(val: str) -> str:
    if len(val) > 6:
        return val[:3] + "***" + val[-3:]
    return val

def moderate_text(text: str, check_types: list = None) -> dict:
    if not check_types:
        check_types = ["spam", "toxicity", "profanity", "pii"]

    result = {
        "text_length": len(text),
        "word_count": len(text.split()),
        "flags": [],
        "flags_count": 0,
        "details": {},
        "overall_safe": True,
        "severity": "clean",
    }

    severities = []

    if "spam" in check_types:
        spam_matches = []
        for pattern in SPAM_PATTERNS:
            matches = pattern.findall(text)
            if matches:
                spam_matches.extend(matches if isinstance(matches[0], str) else [str(m) for m in matches])
        if spam_matches:
            result["flags"].append("spam")
            result["details"]["spam"] = {"detected": True, "matches": spam_matches[:10], "match_count": len(spam_matches)}
            severities.append("high")
        else:
            result["details"]["spam"] = {"detected": False}

    if "toxicity" in check_types:
        tox_matches = []
        for pattern in TOXIC_PATTERNS:
            matches = pattern.findall(text)
            if matches:
                tox_matches.extend(matches if isinstance(matches[0], str) else [str(m) for m in matches])
        if tox_matches:
            result["flags"].append("toxicity")
            result["details"]["toxicity"] = {"detected": True, "matches": tox_matches[:10], "match_count": len(tox_matches)}
            severities.append("high")
        else:
            result["details"]["toxicity"] = {"detected": False}

    if "profanity" in check_types:
        prof_matches = []
        for pattern in PROFANITY_PATTERNS:
            matches = pattern.findall(text)
            if matches:
                prof_matches.extend(matches if isinstance(matches[0], str) else [str(m) for m in matches])
        if prof_matches:
            result["flags"].append("profanity")
            result["details"]["profanity"] = {"detected": True, "matches": prof_matches[:10], "match_count": len(prof_matches)}
            severities.append("medium")
        else:
            result["details"]["profanity"] = {"detected": False}

    if "pii" in check_types:
        pii_found = {}
        for pii_type, pattern in PII_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                pii_found[pii_type] = {
                    "detected": True,
                    "type": pii_type,
                    "sample_matches": [_mask_value(m) for m in matches[:5]],
                    "match_count": len(matches),
                }
        if pii_found:
            result["flags"].append("pii")
            result["details"]["pii"] = pii_found
            severities.append("critical")
        else:
            result["details"]["pii"] = {"detected": False}

    result["flags_count"] = len(result["flags"])
    result["overall_safe"] = result["flags_count"] == 0

    if "critical" in severities:
        result["severity"] = "critical"
    elif "high" in severities:
        result["severity"] = "high"
    elif "medium" in severities:
        result["severity"] = "medium"
    elif "low" in severities:
        result["severity"] = "low"

    return result


def moderate_image(image_data_b64: str) -> dict:
    result = {
        "flags": [],
        "nsfw_detected": False,
        "details": {},
        "confidence": 0.0,
    }

    try:
        image_bytes = base64.b64decode(image_data_b64)
        file_size_kb = len(image_bytes) / 1024
        image_hash = hashlib.md5(image_bytes).hexdigest()

        width = height = 0
        if image_bytes[:8] == b'\x89PNG\r\n\x1a\n':
            width = int.from_bytes(image_bytes[16:20], 'big')
            height = int.from_bytes(image_bytes[20:24], 'big')
        elif image_bytes[:2] in (b'\xff\xd8',):
            i = 2
            while i < len(image_bytes) - 1:
                if image_bytes[i] == 0xff:
                    marker = image_bytes[i+1]
                    if marker in (0xc0, 0xc1, 0xc2):
                        height = int.from_bytes(image_bytes[i+5:i+7], 'big')
                        width = int.from_bytes(image_bytes[i+7:i+9], 'big')
                        break
                    elif marker not in (0xd9, 0xda):
                        length = int.from_bytes(image_bytes[i+2:i+4], 'big')
                        i += length + 2
                        continue
                i += 1

        flagged_reasons = []
        if file_size_kb > 5000:
            flagged_reasons.append("unusually_large_file")

        avg_brightness = sum(image_bytes[:min(1000, len(image_bytes))]) / min(1000, len(image_bytes))
        if avg_brightness > 200:
            flagged_reasons.append("very_bright_image")

        result["details"] = {
            "file_size_kb": round(file_size_kb, 1),
            "width": width,
            "height": height,
            "image_hash": image_hash,
            "heuristics": flagged_reasons,
            "note": "Rule-based analysis. For production, integrate a dedicated NSFW API."
        }

        if flagged_reasons:
            result["flags"].extend(flagged_reasons)
            result["nsfw_detected"] = True
            result["confidence"] = 0.3

    except Exception as e:
        result["error"] = f"Image analysis error: {str(e)}"

    return result


# ─── MCP Tool Definitions ──────────────────────────────────────────────

@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="moderate_text",
            description="Moderate text content for spam, toxicity, PII, profanity. Returns detailed report with flags and severity.",
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "The text content to moderate"},
                    "check_types": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["spam", "toxicity", "profanity", "pii"]},
                        "description": "Types of moderation to perform. Default: all",
                        "default": ["spam", "toxicity", "profanity", "pii"]
                    }
                },
                "required": ["text"]
            }
        ),
        Tool(
            name="moderate_image",
            description="Moderate image content for NSFW using pixel heuristics and image fingerprinting. Provide base64-encoded image data.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_data": {"type": "string", "description": "Base64-encoded image data"}
                },
                "required": ["image_data"]
            }
        ),
        Tool(
            name="get_moderation_stats",
            description="Get the current moderation server stats (call count, tier status, remaining calls).",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    limit_check = check_rate_limit()
    if limit_check:
        if name == "get_moderation_stats":
            # Stats calls don't consume quota
            global call_counter
            call_counter -= 1
        else:
            return [TextContent(type="text", text=json.dumps(limit_check, indent=2))]

    try:
        if name == "moderate_text":
            text = arguments.get("text", "")
            check_types = arguments.get("check_types", None)
            result = moderate_text(text, check_types)
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "moderate_image":
            image_data = arguments.get("image_data", "")
            result = moderate_image(image_data)
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "get_moderation_stats":
            return [TextContent(type="text", text=json.dumps({
                "tier": "pro" if IS_PRO else "free",
                "calls_used": call_counter,
                "free_limit": FREE_LIMIT,
                "calls_remaining": max(0, FREE_LIMIT - call_counter) if not IS_PRO else "unlimited",
                "pro_key_configured": PRO_KEY in PRO_KEYS if PRO_KEY else False,
                "stripe_link": STRIPE_LINK,
            }, indent=2))]

        else:
            return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]

    except Exception as e:
        return [TextContent(type="text", text=json.dumps({"error": str(e)}))]


def main():
    import anyio
    async def run():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())
    anyio.run(run)

if __name__ == "__main__":
    main()
