"""Synthetic service-manual corpus — stand-in for a file repo that
WisdomAI's FunctionAgent would search via MCP."""
from __future__ import annotations

MANUALS: dict[str, dict[str, str]] = {
    "pump-svc-v3": {
        "title": "Imaging-Suite Pump Service Manual v3 (Revision 2025-11)",
        "sections": (
            "## 4.2 Overnight vibration spikes\n"
            "If the pump vibration exceeds 5 mm/s during the overnight "
            "recirculation cycle (typically 02:00-04:00), suspect a partially-"
            "loaded impeller or a frozen condensate trap. Recommended sequence:\n"
            "1. Run the cold-loop drain at 01:30 to clear accumulated condensate.\n"
            "2. Inspect impeller balance weights.\n"
            "3. If spike persists > 2 nights, escalate to a full pump overhaul.\n"
            "\n## 4.3 High-temperature coincident with vibration\n"
            "A simultaneous temperature rise (> 4 °C over baseline) and "
            "vibration spike usually indicates bearing-race wear. Replace "
            "bearings before the next 1000-hour service interval.\n"
        ),
    },
    "hospital-biomed-procedures": {
        "title": "Hospital Biomedical Engineering Procedures Handbook",
        "sections": (
            "## 7 Paging system diagnostics\n"
            "False overnight alarms most often trace to watchdog timeouts on "
            "the SIP trunk. Capture a `sip-debug` trace next time it fires.\n"
        ),
    },
    "cmms-workorder-codes": {
        "title": "CMMS Work-Order Code Reference",
        "sections": (
            "WO codes for pump issues:\n"
            "  PMP-OVHL  — full overhaul (8h, out-of-service overnight)\n"
            "  PMP-BEAR  — bearing replacement (4h)\n"
            "  PMP-IMPB  — impeller balance check (1h)\n"
            "  PMP-CDRN  — condensate drain clear (30m)\n"
        ),
    },
}


def search_manuals(keywords: str) -> list[dict[str, str]]:
    """Return manuals whose sections mention any of the keyword tokens."""
    toks = [t.lower() for t in keywords.split() if len(t) >= 4]
    hits = []
    for mid, m in MANUALS.items():
        text = m["sections"].lower()
        if any(t in text for t in toks):
            hits.append({"manual_id": mid, "title": m["title"],
                         "excerpt": m["sections"][:900]})
    return hits


def fetch_workorder_history(pump_id: str) -> list[dict[str, str]]:
    """Stand-in for CMMS fetch."""
    if pump_id == "pump-14":
        return [
            {"wo_id": "WO-240131", "code": "PMP-IMPB",
             "date": "2024-01-31",
             "summary": "Impeller balance check, noted slight wear"},
            {"wo_id": "WO-251012", "code": "PMP-CDRN",
             "date": "2025-10-12",
             "summary": "Condensate drain cleared"},
        ]
    return []
