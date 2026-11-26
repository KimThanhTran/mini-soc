"""Ships sensor records to the ingestion API: signed batches, a bounded queue, retry with backoff."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime, timezone

import httpx

log = logging.getLogger("sensor")
MAX_SERVER_ERRORS = 5
BACKOFF_START, BACKOFF_MAX = 1.0, 30.0


def signed_headers(sensor_id: str, secret: str, body: bytes) -> dict:
    """Same scheme the API verifies: HMAC-SHA256 over '<unix seconds>.<body>'."""
    ts = int(time.time())
    sig = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return {"X-Sensor-Id": sensor_id, "X-Timestamp": str(ts), "X-Signature": sig, "Content-Type": "application/json"}


class Shipper:
    def __init__(self, source: str, host: str, api_url: str | None = None, sensor_id: str | None = None,
                 secret: str | None = None, max_queue: int = 10_000):
        self.source, self.host = source, host
        self.api_url = (api_url or os.environ.get("API_URL", "http://api:8000")).rstrip("/")
        self.sensor_id = sensor_id or os.environ.get("SENSOR_ID", source)
        self.secret = secret or os.environ.get("SENSOR_SECRET", "")
        self.queue: asyncio.Queue = asyncio.Queue(max_queue)

    def emit(self, data: dict) -> None:
        """Never blocks the honeypot: when the queue is full the record is dropped and counted in the log."""
        event = {"source": self.source, "ts": datetime.now(timezone.utc).isoformat(), "host": self.host, "data": data}
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            log.warning("queue full, dropped a record")

    async def _batch(self) -> list[dict]:
        batch = [await self.queue.get()]
        deadline = time.monotonic() + 1.0
        while len(batch) < 50 and (left := deadline - time.monotonic()) > 0:
            try:
                batch.append(await asyncio.wait_for(self.queue.get(), left))
            except TimeoutError:
                break
        return batch

    async def run(self) -> None:
        delay = BACKOFF_START
        async with httpx.AsyncClient(timeout=5) as client:
            while True:
                batch = await self._batch()
                server_errors = 0
                while True:
                    body = json.dumps({"events": batch}).encode()
                    try:
                        r = await client.post(f"{self.api_url}/api/ingest", content=body,
                                              headers=signed_headers(self.sensor_id, self.secret, body))
                        if r.status_code < 500 and r.status_code != 429:
                            if r.status_code >= 400:
                                log.error("API refused a batch (%s): %s", r.status_code, r.text[:200])
                            delay = BACKOFF_START
                            break
                        if r.status_code >= 500:
                            server_errors += 1
                            if server_errors >= MAX_SERVER_ERRORS:  # a batch the API cannot process must not block the sensor forever
                                log.error("API failed %s times on one batch (%s); dropped %s records", server_errors, r.status_code, len(batch))
                                break
                    except httpx.HTTPError as e:
                        log.warning("API unreachable: %s", e)  # an outage is retried for as long as it lasts
                    await asyncio.sleep(delay)
                    delay = min(delay * 2, BACKOFF_MAX)
