"""Synthetic pump telemetry — vibration + temperature readings.

Pump-14 is intentionally seeded with overnight spikes, so the
W9 telemetry-fusion agent can find a pattern.
"""
from __future__ import annotations
import math
import random
from typing import Any

_RNG = random.Random(7)

_PUMPS = ["pump-10", "pump-11", "pump-12", "pump-13", "pump-14"]


def _gen_readings() -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {p: [] for p in _PUMPS}
    # 7 days × 24 hours × 4 readings/hour
    for p in _PUMPS:
        for day in range(7):
            for hour in range(24):
                for minute in (0, 15, 30, 45):
                    base_vib = 2.1 + 0.2 * math.sin(hour / 4)
                    base_temp = 61.0 + 0.8 * math.sin(hour / 6)
                    vib = base_vib + _RNG.gauss(0, 0.12)
                    temp = base_temp + _RNG.gauss(0, 0.5)
                    # pump-14 goes bad between 2am and 4am every day
                    if p == "pump-14" and 2 <= hour <= 4:
                        vib += 3.5 + _RNG.gauss(0, 0.4)
                        temp += 6.0 + _RNG.gauss(0, 0.6)
                    ts = f"2026-04-{9+day:02d}T{hour:02d}:{minute:02d}:00Z"
                    out[p].append({
                        "ts": ts, "vibration_mm_s": round(vib, 2),
                        "temp_c": round(temp, 1),
                    })
    return out


READINGS = _gen_readings()


def query_timeseries(pump_id: str, start_ts: str, end_ts: str
                     ) -> list[dict[str, Any]]:
    """Return readings for a pump between start/end ISO timestamps."""
    rows = READINGS.get(pump_id, [])
    return [r for r in rows if start_ts <= r["ts"] <= end_ts]


def timeseries_summary(pump_id: str) -> dict[str, Any]:
    """Descriptive stats + overnight-anomaly flag."""
    rows = READINGS.get(pump_id, [])
    if not rows:
        return {"pump_id": pump_id, "error": "unknown pump"}
    vib = [r["vibration_mm_s"] for r in rows]
    temp = [r["temp_c"] for r in rows]
    overnight = [r for r in rows if r["ts"][11:13] in ("02", "03", "04")]
    overnight_vib_avg = (sum(r["vibration_mm_s"] for r in overnight)
                         / len(overnight))
    day_vib = [r for r in rows if r["ts"][11:13] not in ("02", "03", "04")]
    day_vib_avg = sum(r["vibration_mm_s"] for r in day_vib) / len(day_vib)
    return {
        "pump_id": pump_id,
        "n_readings": len(rows),
        "vibration_avg": round(sum(vib) / len(vib), 2),
        "temp_avg": round(sum(temp) / len(temp), 2),
        "overnight_vibration_avg": round(overnight_vib_avg, 2),
        "daytime_vibration_avg": round(day_vib_avg, 2),
        "overnight_spike_detected": overnight_vib_avg > day_vib_avg * 1.5,
    }
