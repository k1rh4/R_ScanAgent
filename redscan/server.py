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
    created_at: float


app = FastAPI(title="RedScan API", version="0.2.0")
agent = RedScanAgent()

MAX_CONCURRENCY = int(os.getenv("REDSCAN_CONCURRENCY", "4"))
QUEUE_SIZE = int(os.getenv("REDSCAN_QUEUE_SIZE", "100"))

queue: asyncio.Queue[Job] = asyncio.Queue(maxsize=QUEUE_SIZE)
results: Dict[str, ScanResult] = {}


async def _worker(worker_id: int):
    while True:
        job = await queue.get()
        try:
            req = job.request
            if req.phase == "triage":
                out = agent.triage(req.data)
            elif req.phase == "probe":
                out = agent.probe(req.data, active=req.active)
            elif req.phase == "deep":
                probe = agent.probe(req.data, active=req.active)
                out = agent.deep_analysis(req.data, probe)
            else:
                probe = agent.probe(req.data, active=req.active)
                analysis = agent.deep_analysis(req.data, probe)
                out = agent.final_exploit(req.data, analysis)
            results[job.id] = ScanResult(status="done", result=out)
        except Exception as e:
            results[job.id] = ScanResult(status="error", error=str(e))
        finally:
            queue.task_done()


@app.on_event("startup")
async def startup():
    for i in range(MAX_CONCURRENCY):
        asyncio.create_task(_worker(i))


@app.get("/health")
def health():
    return {"status": "ok", "queue": queue.qsize(), "concurrency": MAX_CONCURRENCY}


@app.post("/scan", response_model=ScanResponse)
async def scan(req: ScanRequest):
    if req.phase not in {"triage", "probe", "deep", "final"}:
        raise HTTPException(status_code=400, detail="invalid phase")
    job_id = str(uuid.uuid4())
    results[job_id] = ScanResult(status="queued")
    try:
        queue.put_nowait(Job(id=job_id, request=req, created_at=time.time()))
    except asyncio.QueueFull:
        results[job_id] = ScanResult(status="error", error="queue full")
        raise HTTPException(status_code=429, detail="queue full")
    return ScanResponse(job_id=job_id)


@app.get("/result/{job_id}", response_model=ScanResult)
def get_result(job_id: str):
    if job_id not in results:
        raise HTTPException(status_code=404, detail="job not found")
    return results[job_id]
