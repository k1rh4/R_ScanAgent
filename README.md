# RedScan

Burp Suite HTTP History(JSON) 기반으로 치명적 취약점만을 선별/검증하는 자동화 에이전트.

## 설치 가이드

### Docker (Ubuntu 24.04 기반, API 서버)

```bash
docker build -t redscan:latest .
```

실행:

```bash
# API 서버 실행
mkdir -p output runtime
docker run --rm -p 8000:8000 \
  -v "$PWD/output":/app/output \
  -v "$PWD/runtime":/app/runtime \
  -e REDSCAN_OUTPUT_DIR=/app/output \
  -e REDSCAN_SCAN_LOG=/app/runtime/scan.log \
  -e REDSCAN_COMPLETE_PATH_LOG=/app/runtime/complete_path.log \
  redscan:latest
```

docker compose:

```bash
docker compose up --build
```

### Docker 환경변수 설정 방법

1) `.env` 파일 생성 (권장)

```bash
cp .env.example .env
```

예시(`.env`):

```env
# LLM
LLM_PROVIDER=gemini
LLM_MODEL=gemini-1.5-pro
GEMINI_API_KEY=your-gemini-key
# provider별 모델 변수(선택): OPENAI_MODEL / ANTHROPIC_MODEL / GEMINI_MODEL

# Server
REDSCAN_CONCURRENCY=4
REDSCAN_QUEUE_SIZE=100

# Logs/Artifacts
REDSCAN_COMPLETE_PATH_LOG=complete_path.log
REDSCAN_SCAN_LOG=scan.log
REDSCAN_OUTPUT_DIR=output
```

2) `docker run`으로 실행할 때

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

3) `docker compose`로 실행할 때

- `docker-compose.yml`의 `${...}` 값은 프로젝트 루트 `.env`를 자동으로 읽습니다.
- `output/`(리포트/익스 코드)와 `runtime/`(로그/완료 path)가 호스트 디렉토리로 마운트됩니다.
- 실행:

```bash
mkdir -p output runtime
docker compose up --build
```

요청 예시:

```bash
curl -X POST http://localhost:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{"data": {"request": "...", "response": "..."}, "phase": "probe", "active": false}'
```

결과 조회:

```bash
curl http://localhost:8000/result/<job_id>
```

환경 변수:

- `REDSCAN_CONCURRENCY`: 워커 수 (기본 4)
- `REDSCAN_QUEUE_SIZE`: 큐 크기 (기본 100)
- `REDSCAN_RESULT_TTL_SEC`: `/result` 보관 시간(초, 기본 3600)
- `REDSCAN_RESULT_MAX_ITEMS`: `/result` 최대 보관 개수(기본 10000)
- `REDSCAN_COMPLETE_PATH_LOG`: 완료 path 로그 파일 (기본 `complete_path.log`)
- `REDSCAN_SCAN_LOG`: 스캔 진행 로그 파일 (기본 `scan.log`)
- `REDSCAN_OUTPUT_DIR`: 취약점 산출물 디렉토리 (기본 `output`)
- `REDSCAN_ENABLE_COMMIX`: Command Injection 프리검증 사용 여부 (기본 `1`)
- `REDSCAN_ENABLE_FFUF`: Path Traversal/Download 프리검증 사용 여부 (기본 `1`)
- `REDSCAN_TOOL_TIMEOUT`: 외부 도구 실행 타임아웃(초, 기본 45)
- `REDSCAN_SCAN_LOG_MAX_BYTES`: `scan.log` 로테이션 기준 크기(바이트, 기본 10485760)
- `REDSCAN_SCAN_LOG_BACKUP_COUNT`: `scan.log` 백업 파일 개수(기본 5)
- `LLM_PROVIDER`: `openai` | `anthropic` | `gemini`
- `LLM_MODEL`: 공통 모델명(권장, provider별 model env보다 우선순위 낮음)
- `OPENAI_API_KEY`, `OPENAI_MODEL`
- `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL`
- `GEMINI_API_KEY`, `GEMINI_MODEL`
- `LLM_TIMEOUT`: 요청 타임아웃(초)
- `LLM_RETRIES`: 재시도 횟수
- `LLM_RETRY_BACKOFF`: 재시도 백오프(초)
- `LLM_RETRY_MODE`: `exponential` | `fixed`
- `LLM_RETRY_STATUS`: 재시도 대상 HTTP 상태코드 (콤마 구분)

테스트 스크립트 요구사항:

- `jq` 필요
- Ubuntu: `sudo apt-get install -y jq`

### 로컬 설치 (비도커, CLI)

### 1) Python 패키지

```bash
python -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
```

### 2) 외부 도구

- sqlmap 설치

```bash
# Debian/Ubuntu
sudo apt-get install -y sqlmap

# macOS (Homebrew)
brew install sqlmap

# pip (환경에 따라 동작, 권장 아님)
pip install sqlmap
```

## 실행 예시

```bash
python main.py --input burp_packet.json --phase probe
python main.py --input burp_packet.json --phase deep --active
python main.py --input burp_packet.json --phase final --active
```

## 탐지 품질 개선 포인트 (내장)

- Baseline vs Probe 응답 유사도/길이/시간 차이 비교
- SQLi/Command/Traversal/Download에 다중 페이로드 사용
- SQLi는 raw request 기반 `sqlmap -r` 실행
- Upload는 multipart 필드 감지 후 실제 업로드 탐침 시도

## 설정

- `custom_policy.txt` 내용을 시스템 메시지에 병합하여 탐침 우선순위를 커스텀합니다.
- 동일 path 중복 진단 방지: 진단 완료 path는 `complete_path.log`(기본값)에 기록되며, 이후 동일 path 요청은 `SKIPPED`로 반환됩니다.
- 진행 로그: `scan.log`에 JSON Lines 형태로 실시간 기록되며, path별 `no` 번호로 후보/검증 진행 상태를 추적할 수 있습니다.
- `scan.log`는 크기 제한 기반 로테이션을 지원합니다 (`scan.log.1`, `scan.log.2` ...).
- 취약점 산출물: `VERIFIED` 결과가 있으면 `output/<path>/` 아래에 `report.md`와 실행 가능한 `exploit_*` 파일이 생성됩니다.
- `report.md`에는 취약점 설명(타입/벡터/근거)과 함께 재현용 exploit 코드가 함께 포함됩니다.
- `active=true`일 때 `deep` 단계에서 LLM 게이트 후 `commix/ffuf` 프리검증이 동작합니다(도구 미설치 시 스캔은 중단되지 않고 로그에 `tool_not_installed`로 기록).
