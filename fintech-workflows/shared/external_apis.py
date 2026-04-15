"""Real public fintech-reference API wrappers shared across the multi-API workflows.

All endpoints below are free, keyless (or use free-tier keys), and respect standard HTTP:
  * SEC EDGAR                — https://data.sec.gov  (10-K/10-Q filings, Form 4 insider filings)
  * RBI (circulars, FX ref)  — https://www.rbi.org.in / https://www.fbil.org.in
  * OFAC SDN list            — https://www.treasury.gov/ofac/downloads
  * UN sanctions             — https://scsanctions.un.org
  * NSE bulk deals           — https://www.nseindia.com
  * BSE press releases       — https://www.bseindia.com
  * GSTN public verify       — https://services.gst.gov.in
  * Alpha Vantage free tier  — https://www.alphavantage.co  (ALPHAVANTAGE_API_KEY env)
  * openFIGI                 — https://api.openfigi.com

A 15s timeout applies to every call; callers should tolerate empty results
rather than crashing (public feeds occasionally hiccup).
"""
from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request
from typing import Any

# SEC requires a descriptive User-Agent with contact info for EDGAR.
_UA_SEC = "declaw-ai-workflows/1.0 (contact: research@declaw.ai)"
_UA_DEFAULT = "declaw-ai-workflows/1.0"


def _get(url: str, *, headers: dict | None = None, timeout: int = 15) -> bytes:
    req = urllib.request.Request(url, headers={
        "User-Agent": _UA_DEFAULT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _get_json(url: str, *, headers: dict | None = None, timeout: int = 15) -> Any:
    return json.loads(_get(url, headers=headers, timeout=timeout).decode())


# ---------- SEC EDGAR ----------

def edgar_company_facts(cik: str) -> dict[str, Any]:
    """Pull the structured `companyfacts` JSON for a given CIK (zero-padded 10 digits).

    Example: edgar_company_facts('0000320193')  # Apple Inc.
    """
    cik10 = cik.zfill(10)
    url = f"https://data.sec.gov/api/xbrl/companyfacts/CIK{cik10}.json"
    try:
        return _get_json(url, headers={"User-Agent": _UA_SEC})
    except Exception as e:
        return {"error": f"edgar_company_facts failed: {type(e).__name__}"}


def edgar_recent_filings(cik: str, form_type: str = "10-K", limit: int = 5) -> list[dict[str, Any]]:
    cik10 = cik.zfill(10)
    url = f"https://data.sec.gov/submissions/CIK{cik10}.json"
    try:
        data = _get_json(url, headers={"User-Agent": _UA_SEC})
    except Exception as e:
        return [{"error": f"edgar_recent_filings failed: {type(e).__name__}"}]
    recent = (data.get("filings") or {}).get("recent") or {}
    forms = recent.get("form", [])
    dates = recent.get("filingDate", [])
    accs = recent.get("accessionNumber", [])
    out = []
    for f, d, a in zip(forms, dates, accs):
        if f == form_type:
            out.append({"form": f, "filing_date": d, "accession": a, "cik": cik})
            if len(out) >= limit:
                break
    return out


def edgar_form4_insider(cik: str, limit: int = 5) -> list[dict[str, Any]]:
    """Pull recent Form 4 (insider trading) filings for a CIK."""
    return edgar_recent_filings(cik, form_type="4", limit=limit)


# ---------- Sanctions ----------

def ofac_sdn_names(limit: int = 50) -> list[str]:
    """Fetch a slice of names from the OFAC SDN list (XML)."""
    url = "https://www.treasury.gov/ofac/downloads/sdn.xml"
    try:
        xml = _get(url, timeout=25).decode(errors="replace")
    except Exception:
        return []
    names = re.findall(r"<lastName>(.*?)</lastName>", xml)[:limit]
    return names


def is_sanctioned(name: str) -> dict[str, Any]:
    """Quick membership check against OFAC SDN names (substring match).

    Deliberately simple — real SDN matching uses normalised-name scoring.
    """
    try:
        names = ofac_sdn_names(limit=500)
    except Exception:
        names = []
    hits = [n for n in names if name.upper() in n.upper()]
    return {"name": name, "sanctioned": bool(hits), "matched_entries": hits[:5]}


# ---------- Exchange feeds ----------

def nse_bulk_deals_today() -> list[dict[str, Any]]:
    """Latest NSE bulk-deals list (JSON). May 403 without a real browser session
    — fall back to an empty list so workflows don't crash."""
    url = "https://www.nseindia.com/api/historical/cm/bulk"
    try:
        data = _get_json(url, headers={"User-Agent": _UA_DEFAULT,
                                       "Accept": "application/json"})
        return data.get("data", []) if isinstance(data, dict) else []
    except Exception:
        return []


def bse_press_releases(limit: int = 10) -> list[dict[str, Any]]:
    """Best-effort scrape of recent BSE press releases."""
    url = "https://www.bseindia.com/xml-data/corpfiling/AttachHis/CorpannHist.xml"
    try:
        xml = _get(url).decode(errors="replace")
    except Exception:
        return []
    items = re.findall(r"<item>(.*?)</item>", xml, re.S)[:limit]
    return [{"raw": i[:600]} for i in items]


# ---------- RBI / FBIL ----------

def rbi_circulars_rss(limit: int = 10) -> list[dict[str, Any]]:
    """Latest RBI circulars (RSS XML). Public, no key."""
    url = "https://www.rbi.org.in/Scripts/Rss.aspx?Cat=1"
    try:
        xml = _get(url).decode(errors="replace")
    except Exception:
        return []
    items = []
    for m in re.finditer(r"<item>(.*?)</item>", xml, re.S):
        block = m.group(1)
        title = re.search(r"<title>(.*?)</title>", block, re.S)
        link = re.search(r"<link>(.*?)</link>", block, re.S)
        pub = re.search(r"<pubDate>(.*?)</pubDate>", block, re.S)
        items.append({
            "title": (title.group(1).strip() if title else "")[:200],
            "url": (link.group(1).strip() if link else ""),
            "pub_date": (pub.group(1).strip() if pub else ""),
        })
        if len(items) >= limit:
            break
    return items


def fbil_reference_rate(pair: str = "USDINR") -> dict[str, Any]:
    """FBIL reference rate best-effort fetch."""
    url = "https://www.fbil.org.in/"
    try:
        html = _get(url).decode(errors="replace")
    except Exception:
        return {"pair": pair, "rate": None}
    # Look for pair anywhere in the page
    m = re.search(rf"{pair}[^\d]*(\d+\.\d+)", html)
    return {"pair": pair, "rate": float(m.group(1)) if m else None}


# ---------- Alpha Vantage (free key required) ----------

def alphavantage_quote(symbol: str) -> dict[str, Any]:
    key = os.getenv("ALPHAVANTAGE_API_KEY")
    if not key:
        return {"symbol": symbol, "error": "ALPHAVANTAGE_API_KEY not set"}
    q = urllib.parse.urlencode({"function": "GLOBAL_QUOTE", "symbol": symbol, "apikey": key})
    try:
        data = _get_json(f"https://www.alphavantage.co/query?{q}")
        quote = data.get("Global Quote") or {}
        return {
            "symbol": symbol,
            "price": quote.get("05. price"),
            "change_pct": quote.get("10. change percent"),
            "latest_trading_day": quote.get("07. latest trading day"),
        }
    except Exception as e:
        return {"symbol": symbol, "error": f"alphavantage_quote: {type(e).__name__}"}


# ---------- openFIGI ----------

def openfigi_map(ticker: str, exch_code: str = "US") -> list[dict[str, Any]]:
    """Map ticker to FIGI identifiers."""
    url = "https://api.openfigi.com/v3/mapping"
    payload = json.dumps([{"idType": "TICKER", "idValue": ticker, "exchCode": exch_code}]).encode()
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": _UA_DEFAULT})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        if data and isinstance(data, list) and data[0].get("data"):
            return data[0]["data"][:3]
        return []
    except Exception:
        return []


# ---------- GSTN verify (public) ----------

def gstn_taxpayer_verify(gstin: str) -> dict[str, Any]:
    """Best-effort GSTN public-search lookup. In production this requires
    API credentials; the public-facing search page is accessible without."""
    if not re.fullmatch(r"\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]", gstin):
        return {"gstin": gstin, "valid_format": False}
    # We don't hit the live endpoint here (captcha); return a format-valid stub
    # that live verify replaces with a real call.
    return {"gstin": gstin, "valid_format": True,
            "status": "unknown (public-verify requires captcha bypass)"}
