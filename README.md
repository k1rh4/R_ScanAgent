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
docker run --rm -p 8000:8000 -v "$PWD":/work -w /work redscan:latest
```

docker compose:

```bash
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
- `LLM_PROVIDER`: `openai` | `anthropic` | `gemini`
- `OPENAI_API_KEY`, `OPENAI_MODEL`
- `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL`
- `GEMINI_API_KEY`, `GEMINI_MODEL`
- `LLM_TIMEOUT`: 요청 타임아웃(초)
- `LLM_RETRIES`: 재시도 횟수
- `LLM_RETRY_BACKOFF`: 재시도 백오프(초)
- `LLM_RETRY_MODE`: `exponential` | `fixed`
- `LLM_RETRY_STATUS`: 재시도 대상 HTTP 상태코드 (콤마 구분)

`.env` 사용:

```bash
cp .env.example .env
```

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
