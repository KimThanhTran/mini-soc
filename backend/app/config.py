"""Settings come only from the environment; the app refuses to start without real-looking secrets."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

MIN_SECRET = 16


@dataclass(frozen=True)
class Settings:
    database_url: str
    sensor_keys: dict[str, str]  # sensor id -> shared HMAC secret
    analyst_token: str
    ingest_rpm: int = 1200  # requests per minute per sensor
    api_rpm: int = 600  # requests per minute per client for the analyst API
    max_batch: int = 500
    max_body: int = 1_000_000
    ml_enabled: bool = True
    ml_interval: float = 10.0
    extra: dict = field(default_factory=dict)

    def __post_init__(self):
        if len(self.analyst_token) < MIN_SECRET:
            raise ValueError(f"ANALYST_TOKEN must be at least {MIN_SECRET} characters")
        if not self.sensor_keys:
            raise ValueError("SENSOR_KEYS must list at least one sensor as id:secret")
        for sensor, secret in self.sensor_keys.items():
            if len(secret) < MIN_SECRET:
                raise ValueError(f"the secret of sensor {sensor!r} must be at least {MIN_SECRET} characters")

    @classmethod
    def from_env(cls) -> "Settings":
        env = os.environ
        try:
            keys = dict(pair.split(":", 1) for pair in env["SENSOR_KEYS"].split(",") if pair.strip())
            return cls(
                database_url=env["DATABASE_URL"],
                sensor_keys=keys,
                analyst_token=env["ANALYST_TOKEN"],
                ingest_rpm=int(env.get("INGEST_RPM", 1200)),
                api_rpm=int(env.get("API_RPM", 600)),
                ml_enabled=env.get("ML_ENABLED", "1") == "1",
                ml_interval=float(env.get("ML_INTERVAL", 10)),
            )
        except KeyError as missing:
            raise SystemExit(f"missing environment variable {missing}; copy .env.example to .env") from None
