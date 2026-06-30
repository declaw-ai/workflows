"""Synthetic 'data warehouse' for WisdomAI-style workflows.

Three tables modeled as lists of dicts so the workflows can be run
without any DB dependency. Generated deterministically from a fixed seed
so every run reproduces the same numbers — makes demos stable.

Tables:
  appointments — 90 days of clinic appointments with no_show flag
  visits       — completed visits with duration
  claims       — rev-cycle claims keyed to visits
"""
from __future__ import annotations

import random
from datetime import date, timedelta
from typing import Any

_RNG = random.Random(42)
_CLINICS = ["clinic-north", "clinic-south", "clinic-east"]
_PROVIDERS = [f"prov-{i:02d}" for i in range(1, 13)]
_PATIENTS = [f"pat-{i:04d}" for i in range(1, 501)]


def _build() -> tuple[list[dict], list[dict], list[dict]]:
    appts, visits, claims = [], [], []
    start = date(2026, 1, 16)
    for day in range(90):
        d = start + timedelta(days=day)
        n = 35 + _RNG.randint(-6, 10)
        # introduce a week-long no_show spike in mid-Feb to make Q&A interesting
        spike_window = date(2026, 2, 10) <= d <= date(2026, 2, 16)
        for i in range(n):
            clinic = _RNG.choice(_CLINICS)
            provider = _RNG.choice(_PROVIDERS)
            patient = _RNG.choice(_PATIENTS)
            no_show_p = 0.25 if spike_window and clinic == "clinic-north" else 0.08
            no_show = _RNG.random() < no_show_p
            appt_id = f"appt-{day:03d}-{i:03d}"
            appts.append({
                "appt_id": appt_id, "clinic_id": clinic,
                "provider_id": provider, "patient_id": patient,
                "scheduled_date": d.isoformat(),
                "no_show": no_show,
            })
            if not no_show:
                duration = _RNG.choice([15, 20, 30, 45])
                visit_id = f"visit-{day:03d}-{i:03d}"
                visits.append({
                    "visit_id": visit_id, "appt_id": appt_id,
                    "patient_id": patient, "provider_id": provider,
                    "clinic_id": clinic,
                    "visit_date": d.isoformat(),
                    "duration_min": duration,
                    "cpt": _RNG.choice(["99213", "99214", "99215"]),
                })
                claims.append({
                    "claim_id": f"clm-{visit_id}",
                    "visit_id": visit_id,
                    "payer": _RNG.choice(["Aetna", "BCBS", "UHC", "Medicare"]),
                    "billed_amount": _RNG.choice([185, 245, 312, 428]),
                    "status": _RNG.choice(
                        ["paid"] * 7 + ["denied"] * 2 + ["pending"]
                    ),
                })
    return appts, visits, claims


APPOINTMENTS, VISITS, CLAIMS = _build()


# ---------- tiny query helpers (stand-in for warehouse SQL) ----------

def sql_no_show_rate_by_day(start: str, end: str) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, int]] = {}
    for a in APPOINTMENTS:
        if not (start <= a["scheduled_date"] <= end):
            continue
        b = buckets.setdefault(a["scheduled_date"], {"scheduled": 0, "no_show": 0})
        b["scheduled"] += 1
        if a["no_show"]:
            b["no_show"] += 1
    return [
        {"date": d, **b, "no_show_rate": round(b["no_show"] / b["scheduled"], 3)}
        for d, b in sorted(buckets.items())
    ]


def sql_no_show_rate_by_clinic(start: str, end: str) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, int]] = {}
    for a in APPOINTMENTS:
        if not (start <= a["scheduled_date"] <= end):
            continue
        b = buckets.setdefault(a["clinic_id"], {"scheduled": 0, "no_show": 0})
        b["scheduled"] += 1
        if a["no_show"]:
            b["no_show"] += 1
    return [
        {"clinic_id": k, **v,
         "no_show_rate": round(v["no_show"] / v["scheduled"], 3)}
        for k, v in sorted(buckets.items())
    ]


def sql_claims_summary(start: str, end: str) -> dict[str, Any]:
    rows = [c for c in CLAIMS if start <= "2026-03-01" <= end  # simple placeholder
            or True]  # return all for demo
    total = sum(c["billed_amount"] for c in rows)
    denied = sum(c["billed_amount"] for c in rows if c["status"] == "denied")
    return {
        "n_claims": len(rows), "total_billed": total,
        "denied_amount": denied,
        "denial_rate": round(denied / max(total, 1), 3),
    }
