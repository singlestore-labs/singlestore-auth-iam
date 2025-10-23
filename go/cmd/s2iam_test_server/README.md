# s2iam_test_server

Lightweight test server used to exercise SingleStore IAM client libraries. It issues mock JWTs, exposes a public key, records requests, and supports simple failure toggles.

## Install

```bash
go install github.com/singlestore-labs/singlestore-auth-iam/go/cmd/s2iam_test_server@latest
```

## Core Usage (atomic startup + shutdown)

```bash
info=$(mktemp)
s2iam_test_server --port=0 --info-file "$info" --shutdown-on-stdin-close &
srv_pid=$!
while [ ! -s "$info" ]; do sleep 0.05; done
port=$(jq -r '.server_info.port' "$info")
echo "port=$port"
# stop (close stdin)
kill -0 $srv_pid 2>/dev/null && exec 3>/proc/$srv_pid/fd/0 || kill $srv_pid
```

Simpler stop alternative (may send SIGTERM if stdin trick not available):
```bash
kill $srv_pid
```

Info file JSON (minimal shape):
```json
{ "server_info": { "port": 12345, "pid": 4242, "started_at": "RFC3339" } }
```

Wait until the info file exists and is non‑empty, then read the port.

## Endpoints

| Path | Purpose |
|------|---------|
| `/auth/iam/{jwtType}` | Return signed JWT (query: `workspaceGroupID`) |
| `/info/public-key` | RSA public key (PEM) |
| `/info/requests` | JSON log of received requests |
| `/health` | Health probe (JSON) |

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | 8080 | Listen port (0 = random) |
| `--key-size` | 2048 | RSA key size bits |
| `--fail-verification` | false | Force verification failure responses |
| `--return-empty-jwt` | false | Return empty JWT string |
| `--return-error` | false | Always return error response |
| `--error-code` | 500 | Error code when returning error |
| `--error-message` | Internal Server Error | Error message when returning error |
| `--required-audience` | (empty) | Enforce GCP audience claim |
| `--azure-tenant` | common | Azure tenant id |
| `--token-expiry` | 1h | JWT lifetime |
| `--allowed-audiences` | https://authsvc.singlestore.com | Comma separated audiences |
| `--verbose` | false | Verbose logging |
| `--info-file` | (empty) | Atomic JSON server info path |
| `--shutdown-on-stdin-close` | false | Graceful shutdown when stdin reaches EOF |

## Python snippet

```python
import subprocess, json, os, time, tempfile

with tempfile.TemporaryDirectory() as tmp:
  info = os.path.join(tmp, 'srv.json')
  proc = subprocess.Popen([
    's2iam_test_server','--port=0','--info-file',info
  ])
  for _ in range(300):
    if os.path.exists(info) and os.path.getsize(info)>0: break
    time.sleep(0.05)
  port = json.load(open(info))['server_info']['port']
  print('port', port)
  # run tests using port
  # optional: proc.terminate() or proc.stdin.close() to shut down server early
```

## Go snippet

```go
cmd := exec.Command("s2iam_test_server","--port=0","--info-file","info.json")
_ = cmd.Start()
for {
  b, err := os.ReadFile("info.json")
  if err == nil && len(b) > 0 { break }
  time.Sleep(50 * time.Millisecond)
}
var out struct { ServerInfo struct { Port int `json:"port"` } `json:"server_info"` }
f, _ := os.Open("info.json"); _ = json.NewDecoder(f).Decode(&out); f.Close()
fmt.Println("port", out.ServerInfo.Port)
// run tests using out.ServerInfo.Port
// optional: close(cmd.Stdin) to shut down server
```

## Error simulation

Examples:
```bash
s2iam_test_server --fail-verification --info-file f &
s2iam_test_server --return-empty-jwt --info-file f &
s2iam_test_server --return-error --error-code=503 --error-message="Service unavailable" --info-file f &
```

## Request log

`/info/requests` returns JSON array of received requests (method, path, headers, time).

## Public key

`/info/public-key` returns PEM you can feed into JWT verification.

## Notes

Use `--port=0` for parallel test runs. Always prefer `--info-file` + polling over stdout parsing.

