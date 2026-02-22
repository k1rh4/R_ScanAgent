from __future__ import annotations

import argparse
import json
import sys

from redscan.agent import RedScanAgent


def load_input(path: str | None) -> dict:
    if path:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return json.load(sys.stdin)


def main():
    p = argparse.ArgumentParser(description="RedScan Autonomous Red-Team Agent")
    p.add_argument("--input", help="Path to Burp JSON input (else stdin)")
    p.add_argument("--policy", default="custom_policy.txt", help="Path to custom_policy.txt")
    p.add_argument("--active", action="store_true", help="Enable active HTTP probing")
    p.add_argument("--phase", choices=["triage", "probe", "deep", "final"], default="probe")
    args = p.parse_args()

    data = load_input(args.input)
    agent = RedScanAgent(policy_path=args.policy)

    if args.phase == "triage":
        out = agent.triage(data)
    elif args.phase == "probe":
        out = agent.probe(data, active=args.active)
    elif args.phase == "deep":
        probe = agent.probe(data, active=args.active)
        out = agent.deep_analysis(data, probe)
    else:
        probe = agent.probe(data, active=args.active)
        analysis = agent.deep_analysis(data, probe)
        out = agent.final_exploit(data, analysis)

    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
