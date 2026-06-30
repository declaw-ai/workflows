"""Zendesk-style mock support-ticket corpus."""
from __future__ import annotations
from typing import Any

TICKETS: list[dict[str, Any]] = [
    {"id": "T-1001", "date": "2026-02-09", "clinic": "clinic-north",
     "priority": "high",
     "title": "Reminder texts not being sent",
     "body": "Patients at clinic-north report not receiving appointment "
             "reminder texts since the SMS vendor migration on 2026-02-08. "
             "Front desk confirmed — the reminder queue hasn't been flushed."},
    {"id": "T-1002", "date": "2026-02-10", "clinic": "clinic-north",
     "priority": "medium",
     "title": "Front-desk confused about new Aetna PA rule",
     "body": "New rule from BCBS renegotiation is confusing staff. "
             "Mis-keyed prior auths causing schedule churn."},
    {"id": "T-1003", "date": "2026-02-11", "clinic": "clinic-north",
     "priority": "medium",
     "title": "Parking-lot snowstorm closure 2/11",
     "body": "Clinic-north parking lot closed half-day due to snowstorm. "
             "Appointments before 11am were mass-cancelled."},
    {"id": "T-1004", "date": "2026-02-12", "clinic": "clinic-north",
     "priority": "low",
     "title": "Paging system false alarm",
     "body": "Clinic-north paging system fired a false alarm at 3am. "
             "Investigating with facilities."},
    {"id": "T-1005", "date": "2026-01-22", "clinic": "clinic-south",
     "priority": "low",
     "title": "Parking meter not working",
     "body": "Parking meter replacement scheduled. Low priority."},
]


def tickets_search(query: str | None = None,
                   clinic: str | None = None,
                   start: str | None = None,
                   end: str | None = None) -> list[dict[str, Any]]:
    rows = list(TICKETS)
    if clinic:
        rows = [t for t in rows if t["clinic"] == clinic]
    if start:
        rows = [t for t in rows if t["date"] >= start]
    if end:
        rows = [t for t in rows if t["date"] <= end]
    if query:
        q = query.lower()
        rows = [t for t in rows if q in t["title"].lower() or q in t["body"].lower()]
    return rows
