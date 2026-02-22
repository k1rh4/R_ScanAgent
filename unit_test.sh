#!/usr/bin/env bash
set -euo pipefail

BASE_URL=${BASE_URL:-http://localhost:8000}

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
