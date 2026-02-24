![Gemini Architecture](gemini_architecture.png)

# RedScan

Burp Suite HTTP History(JSON) 기반으로 치명적 취약점만 선별/검증하는 자동화 에이전트입니다.

## 요약 Flow (현재 코드 기준)

`request/response 입력 -> 요청 파싱/중복체크 -> 후보 선정 -> 프로빙 -> 휴리스틱/도구검증/LLM 보정 -> 최종 exploit 생성 -> 결과 저장`

```text
[API /scan or CLI]
   -> parse_burp_json(request,response)
   -> dedupe key(METHOD host/path) 예약
   -> phase 실행
      triage: 후보만 뽑음
      probe: 후보 + payload 주입 결과 수집
      deep: probe + 판정(휴리스틱, 도구, LLM 보정)
      final: VERIFIED만 exploit/sqlmap 실행
   -> 결과/아티팩트 저장 + dedupe 완료
```

## 단계별 상세

1. 입력 수신
- API: `/scan` 큐 적재 후 워커가 비동기 처리합니다.
- CLI: `main.py`가 직접 phase를 실행합니다.

2. 패킷 파싱
- `parse_burp_json`이 raw `request/response`를 파싱합니다.
- 현재 탐지 핵심 로직은 `req` 중심이며 `res`는 거의 사용하지 않습니다.

3. 중복 방지/경로 예약
- `METHOD host/path` 키를 기준으로 중복 스캔을 차단합니다.
- 이미 완료되었거나 진행 중인 키는 `SKIPPED` 처리됩니다.

4. 후보 선정
- `discover_candidates_prioritized`가 동작합니다.
- LLM 사용 가능 시 요청 surface 기반 우선순위 후보를 만들고, 불가 시 규칙 기반 fallback을 사용합니다.

5. 프로빙(패킷 재전송)
- 후보 위치(query/body/cookie/header/path)에 payload를 주입해 요청을 재전송합니다.
- 증거는 `status/len/time_delta/similarity/hint` 중심으로 수집됩니다.
- `active=false`면 실제 전송 없이 예상 probe 결과만 생성합니다.

6. Deep 판정
- 휴리스틱으로 `VERIFIED`/`DISCARDED`를 먼저 결정합니다.
- `active=true`면 `commix`/`ffuf` 사전검증을 추가 수행할 수 있습니다.
- `VERIFIED` 결과는 LLM으로 다운그레이드 전용 재검토(`KEEP` 또는 `DISCARDED`)를 거칩니다.

7. Final 단계
- `VERIFIED`만 처리합니다.
- SQLi는 `sqlmap -r <raw_request>`로 최종 검증합니다.
- 그 외 유형은 재현용 Python exploit 스크립트를 생성합니다.

## LLM이 쓰이는 시점 (현재 코드상 4곳)

1. 후보 우선순위 선정
- 요청 surface를 기반으로 JSON 후보 집합을 생성합니다.

2. 비싼 도구 실행 게이트
- `HIGH/LOW`로 `commix/ffuf` 실행 여부를 결정합니다.

3. 다운그레이드 전용 검토
- 이미 `VERIFIED`인 결과를 `DISCARDED`로 낮출지 판단합니다.

4. IDOR 판정
- IDOR 프로빙 응답을 기반으로 `VERIFIED`/`DISCARDED`를 보수적으로 판단합니다.

## 사용 Tool 맵

- HTTP 재전송/프로빙: `requests`
- Command Injection 사전검증: `commix`
- Traversal/Download 사전검증: `ffuf`
- SQLi 최종검증: `sqlmap`
- 재현 코드 생성: Python exploit script

## 설치 가이드

### Docker (Ubuntu 24.04 기반, API 서버)

```bash
docker build -t redscan:latest .
```

실행:

```bash
mkdir -p output runtime
docker run --rm -p 8000:8000 \
  --env-file .env \
  -v "$PWD/output":/app/output \
  -v "$PWD/runtime":/app/runtime \
  -e REDSCAN_OUTPUT_DIR=/app/output \
  -e REDSCAN_SCAN_LOG=/app/runtime/scan.log \
  -e REDSCAN_COMPLETE_PATH_LOG=/app/runtime/complete_path.log \
  redscan:latest
```

`docker compose`:

```bash
mkdir -p output runtime
docker compose up --build
```

## 환경 변수

- `REDSCAN_CONCURRENCY`: 워커 수 (기본 `4`)
- `REDSCAN_QUEUE_SIZE`: 큐 크기 (기본 `100`)
- `REDSCAN_RESULT_TTL_SEC`: `/result` 보관 시간(초, 기본 `3600`)
- `REDSCAN_RESULT_MAX_ITEMS`: `/result` 최대 보관 개수(기본 `10000`)
- `REDSCAN_COMPLETE_PATH_LOG`: 완료 path 로그 파일 (기본 `complete_path.log`)
- `REDSCAN_SCAN_LOG`: 스캔 로그 파일 (기본 `scan.log`)
- `REDSCAN_OUTPUT_DIR`: 산출물 디렉토리 (기본 `output`)
- `REDSCAN_ENABLE_COMMIX`: `commix` 사용 여부 (기본 `1`)
- `REDSCAN_ENABLE_FFUF`: `ffuf` 사용 여부 (기본 `1`)
- `REDSCAN_TOOL_TIMEOUT`: 외부 도구 타임아웃(초, 기본 `45`)
- `REDSCAN_SCAN_LOG_MAX_BYTES`: 로그 로테이션 기준 크기 (기본 `10485760`)
- `REDSCAN_SCAN_LOG_BACKUP_COUNT`: 로그 백업 개수 (기본 `5`)
- `REDSCAN_MAX_LLM_CANDIDATES`: LLM 후보 상한 (기본 `9`, 최대 `9`)
- `LLM_PROVIDER`: `openai` | `anthropic` | `gemini` (기본 `openai`)
- `LLM_MODEL`: 공통 모델명
- `OPENAI_API_KEY`, `OPENAI_BASE_URL`(기본 `http://localhost:8000/v1`), `OPENAI_MODEL`(기본 `gpt-5`)
- `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL`
- `GEMINI_API_KEY`, `GEMINI_MODEL`
- `LLM_TIMEOUT`, `LLM_RETRIES`, `LLM_RETRY_BACKOFF`, `LLM_RETRY_MODE`, `LLM_RETRY_STATUS`

## 실행 예시

### API

```bash
curl -X POST http://localhost:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{"data": {"request": "...", "response": "..."}, "phase": "probe", "active": false}'

curl http://localhost:8000/result/<job_id>
```

### CLI

```bash
python3 main.py --input samples/cli_stdin_sample.json --phase triage
python3 main.py --input samples/cli_stdin_sample.json --phase probe --active
python3 main.py --input samples/cli_stdin_sample.json --phase deep --active
python3 main.py --input samples/cli_stdin_sample.json --phase final --active
```

`--input` 없이 실행하면 `stdin` JSON 입력을 사용합니다.

```bash
cat samples/cli_stdin_sample.json | python3 main.py --phase probe
```

## Phase별 샘플 출력(JSON)

### 1) `triage`

```json
{
  "analysis_status": "PROBING",
  "findings": [
    {
      "id": "8f0a8d56-2f37-4e16-9c48-6f4c3b26dc42",
      "type": "SQL Injection",
      "vector": "id/query",
      "reasoning": "Parameter name suggests sensitive sink.",
      "action": {
        "tool": "pending",
        "payload": ""
      },
      "verification_evidence": ""
    }
  ]
}
```

### 2) `probe`

```json
{
  "analysis_status": "PROBING",
  "findings": [
    {
      "id": "42c5dd21-1131-4689-ad74-b3d8e6ea6638",
      "type": "Path Traversal",
      "vector": "__path__/path",
      "reasoning": "URL path contains traversal patterns.",
      "action": {
        "tool": "python_script",
        "payload": "../etc/hosts"
      },
      "verification_evidence": "status=200->200 len=1200->1450 time_delta=0.04s similarity=0.72 hint=/etc/hosts path_hint=/download"
    }
  ]
}
```

### 3) `deep`

```json
{
  "analysis_status": "VERIFIED",
  "findings": [
    {
      "id": "42c5dd21-1131-4689-ad74-b3d8e6ea6638",
      "type": "Path Traversal",
      "vector": "__path__/path",
      "reasoning": "URL path contains traversal patterns.",
      "action": {
        "tool": "python_script",
        "payload": "../etc/hosts"
      },
      "verification_evidence": "status=200->200 len=1200->1450 time_delta=0.04s similarity=0.72 hint=/etc/hosts ffuf=confirmed",
      "analysis_status": "VERIFIED"
    }
  ]
}
```

### 4) `final`

```json
{
  "analysis_status": "VERIFIED",
  "findings": [
    {
      "id": "b11bce2a-0de0-44c0-9d5c-a9f2cb788f87",
      "type": "SQL Injection",
      "vector": "id/query",
      "reasoning": "Parameter name suggests sensitive sink.",
      "action": {
        "tool": "sqlmap",
        "payload": "sqlmap -r /tmp/redscan_xxx.txt -p id --batch --random-agent --level 2 --risk 2"
      },
      "verification_evidence": "status=200->500 len=1100->1800 time_delta=0.03s similarity=0.64 hint=sql sqlmap=confirmed",
      "analysis_status": "VERIFIED"
    }
  ]
}
```

### 5) 중복 경로(`SKIPPED`)

```json
{
  "analysis_status": "SKIPPED",
  "path": "example.com/download",
  "reason": "path already completed or in progress",
  "findings": []
}
```

### 6) API `/result/<job_id>` 래퍼

```json
{
  "status": "done",
  "result": {
    "analysis_status": "PROBING",
    "findings": []
  },
  "error": null
}
```

## 산출물/로그

- 중복 키 로그: `complete_path.log`
- 진행 로그(JSON Lines): `scan.log`
- 취약점 산출물: `output/<path>/`
- `VERIFIED` 결과가 있으면 `report.md`, `exploit_*` 파일이 생성됩니다.

## 로컬 설치 (비도커)

```bash
python3 -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

외부 도구는 환경에 맞게 설치합니다.

- `sqlmap` (최종 SQLi 검증)
- `commix` (Command Injection 사전검증)
- `ffuf` (Traversal/Download 사전검증)
