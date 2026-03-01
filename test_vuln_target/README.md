# test_vuln_target

Intentionally vulnerable FastAPI service for validating RedScan detection.

## Vulnerable Paths

1. SQL Injection: `POST /vuln/sqli`
2. Command Injection: `POST /vuln/cmd`
3. Path Traversal: `POST /vuln/traversal`
4. Unrestricted File Upload: `POST /vuln/upload`
5. Unrestricted File Download: `POST /vuln/download`
6. IDOR: `POST /vuln/idor/orders/{order_id}`
7. Unauthenticated API Access: `POST /api/admin/metrics`

## Run

```bash
cd test_vuln_target
python3 -m uvicorn app:app --host 0.0.0.0 --port 8081
```

Open `http://127.0.0.1:8081`.

## Note

This service is intentionally insecure. Use only in local testing environments.
