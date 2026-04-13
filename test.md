Start MCP server in HTTP/SSE mode:

```bash
export GITHUB_TOKEN=<your-token>
./bin/linux_amd64/ghqr mcp --mode http --addr :8080

```

Discover SSE endpoint:

```bash
curl -N http://localhost:8080/sse
```

Initialize MCP Session:

```bash
curl -X POST "http://localhost:8080/message?sessionId=81613ef5-840b-4229-a982-0106ddab2374" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "capabilities": {},
      "clientInfo": { "name": "demo-client", "version": "1.0" }
    }
  }'
```

List tools:

```bash
  curl -X POST "http://localhost:8080/message?sessionId=81613ef5-840b-4229-a982-0106ddab2374" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list",
    "params": {}
  }'
```

  Invoke scan tool:

```bash
  curl -X POST "http://localhost:8080/message?sessionId=81613ef5-840b-4229-a982-0106ddab2374" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "scan",
      "arguments": {
        "organizations": ["hectorbdemoorg"]
      }
    }
  }'
```