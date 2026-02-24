#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def normalize_http_text(text: str) -> str:
    # Normalize mixed newlines to LF first, then convert to HTTP-style CRLF.
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.replace("\n", "\r\n")


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create JSON packet from request/response text files."
    )
    parser.add_argument("--request", default="request.txt", help="Request text file path")
    parser.add_argument("--response", default="response.txt", help="Response text file path")
    parser.add_argument("--output", default="brup_packet.json", help="Output JSON file path")
    args = parser.parse_args()

    request_path = Path(args.request)
    response_path = Path(args.response)
    output_path = Path(args.output)

    data = {
        "request": normalize_http_text(read_text(request_path)),
        "response": normalize_http_text(read_text(response_path)),
    }

    output_path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Created {output_path}")


if __name__ == "__main__":
    main()
