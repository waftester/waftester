# n8n Workflow Templates for WAFtester

Three ready-to-import n8n workflow templates that connect to WAFtester's MCP server.

## Templates

### 1. AI WAF Security Agent (`ai-waf-security-agent.json`)

Conversational WAF testing powered by an AI agent with full access to WAFtester's 27 MCP tools.

**Flow:** Chat Trigger → AI Agent + MCP Client → interactive security testing

The AI agent understands the full WAFtester workflow (detect → discover → learn → scan → bypass → assess) and drives it conversationally. Users type natural language like "scan example.com for SQLi" and the agent calls the right tools.

**Requires:** OpenAI API key (or swap the LLM sub-node for Anthropic, Ollama, etc.)

### 2. Scheduled WAF Audit (`scheduled-waf-audit.json`)

Weekly automated WAF assessment with Slack reporting.

**Flow:** Cron (Monday 3 AM) → Detect WAF → Assess → Wait → Poll → Route by grade → Slack

Runs `detect_waf` then `assess` against a target, waits for the async task to complete, and sends results to Slack. Routes to different Slack messages based on pass/fail.

**Requires:** Slack credentials, `WAF_TARGET_URL` environment variable

### 3. Post-Deploy Security Gate (`post-deploy-waf-gate.json`)

CI/CD webhook that blocks deployments failing WAF checks.

**Flow:** Webhook (POST) → Detect WAF → Scan → Wait → Poll → Parse → Pass/Fail HTTP response

Your CI/CD pipeline POSTs `{"target": "https://staging.example.com", "categories": ["sqli", "xss"]}` to the webhook. The workflow scans, and returns HTTP 200 (pass) or 422 (fail) with detection rate and bypass details. The pipeline can gate on the response.

**Requires:** `WAF_PASS_THRESHOLD` environment variable (default: 80%)

## Quick Start

```bash
cd n8n-templates
docker compose up -d
```

Open http://localhost:5678, create an account, then **Import from File** to load any template JSON.

Set environment variables in n8n Settings → Variables:
- `WAFTESTER_SSE_URL` — SSE endpoint for the MCP Client Tool node (default: `http://waftester:8080/sse`)
- `WAFTESTER_MCP_URL` — Streamable HTTP endpoint for JSON-RPC calls (default: `http://waftester:8080/mcp`)
- `WAF_TARGET_URL` — your target for the scheduled audit
- `WAF_PASS_THRESHOLD` — minimum detection rate (default 80)

## WAFtester MCP Endpoints

| Endpoint | Transport | Use Case |
|----------|-----------|----------|
| `/sse` | SSE (legacy) | n8n MCP Client Tool node |
| `/mcp` | Streamable HTTP | Direct JSON-RPC calls from HTTP Request nodes |
| `/health` | HTTP GET | Healthchecks and readiness probes |

The AI agent template uses `/sse` via the MCP Client Tool node. The scheduled audit and deploy gate templates use `/mcp` via HTTP Request nodes with raw JSON-RPC payloads.

## Publishing to n8n.io

1. Import a template into n8n and verify it works
2. Export the workflow JSON (Workflow menu → Export)
3. Submit via the [n8n Creator Hub](https://www.notion.so/n8n/n8n-Creator-hub-7bd2cbe0fce0449198ecb23ff4a2f76f)
4. Optionally apply for [Verified Creator](https://creators.n8n.io/) status
