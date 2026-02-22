from __future__ import annotations

import argparse
import json
import os
import sys

from redscan.agent import RedScanAgent
from redscan.output_writer import OutputWriter
from redscan.path_tracker import CompletedPathTracker
from redscan.scan_logger import ScanLogger


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
    path_tracker = CompletedPathTracker(os.getenv("REDSCAN_COMPLETE_PATH_LOG", "complete_path.log"))
    scan_logger = ScanLogger(os.getenv("REDSCAN_SCAN_LOG", "scan.log"))
    output_writer = OutputWriter(os.getenv("REDSCAN_OUTPUT_DIR", "output"))
    path = path_tracker.extract_path(data)
    dedupe_key = path_tracker.extract_dedupe_key(data)
    if not path_tracker.try_reserve(dedupe_key):
        scan_logger.log(
            path=path,
            phase=args.phase,
            event="job_skipped",
            message="request skipped because path already completed or in progress",
        )
        print(
            json.dumps(
                {
                    "analysis_status": "SKIPPED",
                    "path": path,
                    "reason": "path already completed or in progress",
                    "findings": [],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    scan_logger.log(path=path, phase=args.phase, event="job_start", message="cli scan started")
    agent = RedScanAgent(policy_path=args.policy, scan_logger=scan_logger)
    try:
        if args.phase == "triage":
            out = agent.triage(data, path=path)
        elif args.phase == "probe":
            out = agent.probe(data, active=args.active, path=path)
        elif args.phase == "deep":
            probe = agent.probe(data, active=args.active, path=path)
            out = agent.deep_analysis(data, probe, path=path, active=args.active)
        else:
            probe = agent.probe(data, active=args.active, path=path)
            analysis = agent.deep_analysis(data, probe, path=path, active=args.active)
            out = agent.final_exploit(data, analysis, path=path)

        print(json.dumps(out, ensure_ascii=False, indent=2))
        try:
            artifacts = output_writer.write(data, path, args.phase, out)
            if artifacts:
                scan_logger.log(
                    path=path,
                    phase=args.phase,
                    event="artifacts_written",
                    message=f"artifacts generated count={len(artifacts)} files={artifacts}",
                )
        except Exception as e:
            scan_logger.log(
                path=path,
                phase=args.phase,
                event="artifacts_error",
                message=f"artifact generation failed: {e}",
            )
    except Exception:
        path_tracker.mark_failed(dedupe_key)
        raise
    try:
        path_tracker.mark_completed(dedupe_key)
    except Exception as e:
        path_tracker.mark_failed(dedupe_key)
        scan_logger.log(
            path=path,
            phase=args.phase,
            event="path_mark_error",
            message=f"path complete mark failed: {e}",
        )
    scan_logger.log(path=path, phase=args.phase, event="job_end", message="cli scan completed")


if __name__ == "__main__":
    main()
