from __future__ import annotations

import asyncio
import os
import time
import uuid
from dataclasses import dataclass
from typing import Dict, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .agent import RedScanAgent
from .output_writer import OutputWriter
from .path_tracker import CompletedPathTracker
from .scan_logger import ScanLogger


class ScanRequest(BaseModel):
    data: dict
    phase: str = "probe"  # triage | probe | deep | final
    active: bool = False


class ScanResponse(BaseModel):
    job_id: str


class ScanResult(BaseModel):
    status: str
    result: Optional[dict] = None
    error: Optional[str] = None


@dataclass
class Job:
    id: str
    request: ScanRequest
    path: str
    created_at: float


app = FastAPI(title="RedScan API", version="0.2.0")
scan_logger = ScanLogger(os.getenv("REDSCAN_SCAN_LOG", "scan.log"))
agent = RedScanAgent(scan_logger=scan_logger)
path_tracker = CompletedPathTracker(os.getenv("REDSCAN_COMPLETE_PATH_LOG", "complete_path.log"))
output_writer = OutputWriter(os.getenv("REDSCAN_OUTPUT_DIR", "output"))

MAX_CONCURRENCY = int(os.getenv("REDSCAN_CONCURRENCY", "4"))
QUEUE_SIZE = int(os.getenv("REDSCAN_QUEUE_SIZE", "100"))
RESULT_TTL_SEC = int(os.getenv("REDSCAN_RESULT_TTL_SEC", "3600"))
RESULT_MAX_ITEMS = int(os.getenv("REDSCAN_RESULT_MAX_ITEMS", "10000"))

queue: asyncio.Queue[Job] = asyncio.Queue(maxsize=QUEUE_SIZE)
results: Dict[str, ScanResult] = {}
result_timestamps: Dict[str, float] = {}


def _set_result(job_id: str, result: ScanResult) -> None:
    results[job_id] = result
    result_timestamps[job_id] = time.time()


def _prune_results(now: float | None = None) -> None:
    ts_now = now or time.time()

    expired = [
        job_id
        for job_id, created in result_timestamps.items()
        if ts_now - created > RESULT_TTL_SEC
    ]
    for job_id in expired:
        result_timestamps.pop(job_id, None)
        results.pop(job_id, None)

    if len(results) <= RESULT_MAX_ITEMS:
        return

    overflow = len(results) - RESULT_MAX_ITEMS
    ordered = sorted(result_timestamps.items(), key=lambda item: item[1])
    for job_id, _ in ordered[:overflow]:
        result_timestamps.pop(job_id, None)
        results.pop(job_id, None)


async def _worker(worker_id: int):
    while True:
        job = await queue.get()
        req = job.request
        path = job.path
        try:
            _prune_results()
            scan_logger.log(
                path=path,
                phase=req.phase,
                event="job_start",
                message=f"job started id={job.id} worker={worker_id} active={req.active}",
            )
            if req.phase == "triage":
                out = agent.triage(req.data, path=path)
            elif req.phase == "probe":
                out = agent.probe(req.data, active=req.active, path=path)
            elif req.phase == "deep":
                probe = agent.probe(req.data, active=req.active, path=path)
                out = agent.deep_analysis(req.data, probe, path=path, active=req.active)
            else:
                probe = agent.probe(req.data, active=req.active, path=path)
                analysis = agent.deep_analysis(req.data, probe, path=path, active=req.active)
                out = agent.final_exploit(req.data, analysis, path=path)

            try:
                artifacts = output_writer.write(req.data, path, req.phase, out)
                if artifacts:
                    scan_logger.log(
                        path=path,
                        phase=req.phase,
                        event="artifacts_written",
                        message=f"artifacts generated count={len(artifacts)} files={artifacts}",
                    )
            except Exception as e:
                scan_logger.log(
                    path=path,
                    phase=req.phase,
                    event="artifacts_error",
                    message=f"artifact generation failed: {e}",
                )

            _set_result(job.id, ScanResult(status="done", result=out))
            try:
                path_tracker.mark_completed(path)
            except Exception as e:
                scan_logger.log(
                    path=path,
                    phase=req.phase,
                    event="path_mark_error",
                    message=f"path complete mark failed: {e}",
                )
            scan_logger.log(
                path=path,
                phase=req.phase,
                event="job_end",
                message=f"job completed id={job.id} status=done",
            )
        except Exception as e:
            _set_result(job.id, ScanResult(status="error", error=str(e)))
            try:
                path_tracker.mark_failed(path)
            except Exception:
                pass
            try:
                scan_logger.log(
                    path=path,
                    phase=req.phase,
                    event="job_error",
                    message=f"job failed id={job.id} error={e}",
                )
            except Exception:
                pass
        finally:
            queue.task_done()


@app.on_event("startup")
async def startup():
    for i in range(MAX_CONCURRENCY):
        asyncio.create_task(_worker(i))


@app.get("/health")
def health():
    return {
        "status": "ok",
        "queue": queue.qsize(),
        "concurrency": MAX_CONCURRENCY,
        "completed_paths": path_tracker.completed_count(),
    }


@app.post("/scan", response_model=ScanResponse)
async def scan(req: ScanRequest):
    if req.phase not in {"triage", "probe", "deep", "final"}:
        raise HTTPException(status_code=400, detail="invalid phase")
    job_id = str(uuid.uuid4())
    _prune_results()
    try:
        path = path_tracker.extract_path(req.data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"invalid packet data: {e}") from e

    if not path_tracker.try_reserve(path):
        scan_logger.log(
            path=path,
            phase=req.phase,
            event="job_skipped",
            message="request skipped because path already completed or in progress",
        )
        _set_result(
            job_id,
            ScanResult(
                status="done",
                result={
                    "analysis_status": "SKIPPED",
                    "path": path,
                    "reason": "path already completed or in progress",
                    "findings": [],
                },
            ),
        )
        return ScanResponse(job_id=job_id)

    _set_result(job_id, ScanResult(status="queued"))
    try:
        queue.put_nowait(Job(id=job_id, request=req, path=path, created_at=time.time()))
    except asyncio.QueueFull:
        try:
            path_tracker.mark_failed(path)
        except Exception:
            pass
        _set_result(job_id, ScanResult(status="error", error="queue full"))
        raise HTTPException(status_code=429, detail="queue full")
    return ScanResponse(job_id=job_id)


@app.get("/result/{job_id}", response_model=ScanResult)
def get_result(job_id: str):
    _prune_results()
    if job_id not in results:
        raise HTTPException(status_code=404, detail="job not found")
    return results[job_id]
