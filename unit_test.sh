#!/usr/bin/env bash
set -euo pipefail

resolve_base_url() {
  if [[ -n "${BASE_URL:-}" ]]; then
    echo "$BASE_URL"
    return 0
  fi

  local probe_path=${BASE_URL_PROBE_PATH:-/scan}
  local candidates=(
    "http://127.0.0.1:8000"
    "http://localhost:8000"
    "http://host.docker.internal:8000"
  )

  for candidate in "${candidates[@]}"; do
    local status
    status=$(curl -sS -m 2 -o /dev/null -w '%{http_code}' "$candidate$probe_path" || true)
    if [[ "$status" == "200" || "$status" == "401" || "$status" == "403" || "$status" == "405" || "$status" == "422" ]]; then
      echo "$candidate"
      return 0
    fi
  done

  echo "Unable to reach RedScan API on '$probe_path'. Set BASE_URL explicitly (e.g. BASE_URL=http://host.docker.internal:8000)." >&2
  return 1
}

BASE_URL=$(resolve_base_url)
echo "Using BASE_URL=$BASE_URL"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for parsing JSON in this test."
  exit 1
fi

PAYLOAD=$(cat samples/burp_packet.json)

JOB_ID=$(curl -s -X POST "$BASE_URL/scan" \
  -H 'Content-Type: application/json' \
  -d "{\"data\": $PAYLOAD, \"phase\": \"probe\", \"active\": false}" | jq -r .job_id)

if [[ -z "$JOB_ID" || "$JOB_ID" == "null" ]]; then
  echo "Failed to start job"
  exit 1
fi

echo "Job ID: $JOB_ID"

for i in {1..20}; do
  RESP=$(curl -s "$BASE_URL/result/$JOB_ID")
  STATUS=$(echo "$RESP" | jq -r .status)
  if [[ "$STATUS" == "done" ]]; then
    echo "$RESP" | jq .
    exit 0
  elif [[ "$STATUS" == "error" ]]; then
    echo "$RESP" | jq .
    exit 1
  fi
  sleep 0.5
done

echo "Timeout waiting for result"
exit 1
