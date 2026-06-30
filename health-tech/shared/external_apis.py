"""Real public-health-API tool wrappers shared across the multi-API workflows.

All endpoints below are free, keyless, and respect standard HTTP:
  * RxNav (NLM)             — https://rxnav.nlm.nih.gov/REST
  * openFDA drug (FDA)      — https://api.fda.gov/drug
  * ClinicalTrials.gov v2   — https://clinicaltrials.gov/api/v2
  * PubMed E-utilities (NCBI) — https://eutils.ncbi.nlm.nih.gov/entrez/eutils

Rate limits and a 15s timeout apply to every call; they are best-effort
(public APIs occasionally hiccup — callers should be able to tolerate
empty results rather than crashing).
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Any


def _get_json(url: str, timeout: int = 15) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


# ---------- RxNav (NLM) ----------

def rxnorm_normalize(drug_name: str) -> dict[str, Any]:
    """Map a free-text drug name to its best-match RxCUI via RxNav."""
    q = urllib.parse.urlencode({"term": drug_name, "maxEntries": 1})
    url = f"https://rxnav.nlm.nih.gov/REST/approximateTerm.json?{q}"
    try:
        data = _get_json(url)
        matches = (data.get("approximateGroup") or {}).get("candidate") or []
        if matches:
            m = matches[0]
            return {"rxcui": m.get("rxcui"), "name": m.get("name"), "score": m.get("score")}
    except Exception as e:
        return {"error": f"rxnorm_normalize failed: {type(e).__name__}"}
    return {"rxcui": None, "name": None}


def drug_interactions_from_fda(drug_names: list[str]) -> list[dict[str, Any]]:
    """Pull the `drug_interactions` section of each drug's FDA label from
    openFDA. RxNav's `/interaction/list` endpoint was retired in Jan 2024,
    so we read the label text directly — this is the same content that
    appears on the prescribing information (SPL). Returns one entry per
    drug with the raw FDA interaction text snipped to 800 chars."""
    out: list[dict[str, Any]] = []
    for name in drug_names:
        if not name:
            continue
        search = urllib.parse.quote(f'openfda.generic_name:"{name}"')
        url = f"https://api.fda.gov/drug/label.json?search={search}&limit=1"
        try:
            data = _get_json(url)
            results = data.get("results") or []
            if not results:
                # try brand name
                search_b = urllib.parse.quote(f'openfda.brand_name:"{name}"')
                url_b = f"https://api.fda.gov/drug/label.json?search={search_b}&limit=1"
                try:
                    data = _get_json(url_b)
                    results = data.get("results") or []
                except Exception:
                    pass
            if not results:
                out.append({"drug": name, "interactions_text": None})
                continue
            r = results[0]
            text = " ".join(r.get("drug_interactions", []))[:800] or None
            out.append({"drug": name, "interactions_text": text})
        except Exception as e:
            out.append({"drug": name, "error": f"{type(e).__name__}"})
    return out


# ---------- openFDA drug ----------

def openfda_adverse_events(drug_name: str, limit: int = 5) -> dict[str, Any]:
    """Top adverse-event reactions reported for a drug, from openFDA."""
    search = urllib.parse.quote(f'patient.drug.medicinalproduct:"{drug_name}"')
    url = (f"https://api.fda.gov/drug/event.json?search={search}"
           f"&count=patient.reaction.reactionmeddrapt.exact&limit={limit}")
    try:
        data = _get_json(url)
        return {
            "drug": drug_name,
            "top_reactions": [
                {"reaction": r.get("term"), "count": r.get("count")}
                for r in (data.get("results") or [])[:limit]
            ],
        }
    except Exception:
        return {"drug": drug_name, "top_reactions": []}


def openfda_label(drug_name: str) -> dict[str, Any]:
    """FDA-approved label sections for a drug (first match), from openFDA."""
    search = urllib.parse.quote(f'openfda.generic_name:"{drug_name}"')
    url = f"https://api.fda.gov/drug/label.json?search={search}&limit=1"
    try:
        data = _get_json(url)
        results = data.get("results") or []
        if not results:
            return {"drug": drug_name, "label": None}
        r = results[0]
        return {
            "drug": drug_name,
            "indications": " ".join(r.get("indications_and_usage", []))[:600],
            "warnings": " ".join(r.get("warnings", []) or r.get("warnings_and_cautions", []))[:600],
            "dosage": " ".join(r.get("dosage_and_administration", []))[:600],
        }
    except Exception:
        return {"drug": drug_name, "label": None}


# ---------- ClinicalTrials.gov v2 ----------

def ctgov_search(condition: str, status: str = "RECRUITING",
                 page_size: int = 5) -> list[dict[str, Any]]:
    """Search live ClinicalTrials.gov registry by condition."""
    q = urllib.parse.urlencode({
        "query.cond": condition,
        "filter.overallStatus": status,
        "pageSize": page_size,
        "fields": "NCTId,BriefTitle,OverallStatus,Phase,Condition",
    })
    url = f"https://clinicaltrials.gov/api/v2/studies?{q}"
    try:
        data = _get_json(url)
        out: list[dict[str, Any]] = []
        for s in (data.get("studies") or [])[:page_size]:
            p = s.get("protocolSection") or {}
            idm = p.get("identificationModule") or {}
            stm = p.get("statusModule") or {}
            cdm = p.get("conditionsModule") or {}
            dsm = p.get("designModule") or {}
            out.append({
                "nct_id": idm.get("nctId"),
                "title": idm.get("briefTitle"),
                "status": stm.get("overallStatus"),
                "phase": (dsm.get("phases") or [None])[0],
                "conditions": cdm.get("conditions") or [],
            })
        return out
    except Exception as e:
        return [{"error": f"ctgov_search failed: {type(e).__name__}"}]


def ctgov_detail(nct_id: str) -> dict[str, Any]:
    """Pull full study detail (eligibility) for a single NCT ID."""
    url = f"https://clinicaltrials.gov/api/v2/studies/{nct_id}"
    try:
        data = _get_json(url)
        p = data.get("protocolSection") or {}
        elig = p.get("eligibilityModule") or {}
        return {
            "nct_id": nct_id,
            "eligibility_criteria": (elig.get("eligibilityCriteria") or "")[:2000],
            "minimum_age": elig.get("minimumAge"),
            "maximum_age": elig.get("maximumAge"),
            "sex": elig.get("sex"),
            "healthy_volunteers": elig.get("healthyVolunteers"),
        }
    except Exception as e:
        return {"nct_id": nct_id, "error": f"{type(e).__name__}"}


# ---------- PubMed E-utilities ----------

def pubmed_search(query: str, retmax: int = 5) -> list[str]:
    """Return a list of PMIDs matching the query (most-recent first)."""
    q = urllib.parse.urlencode({
        "db": "pubmed", "term": query, "retmax": retmax,
        "retmode": "json", "sort": "most+recent",
    })
    url = f"https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi?{q}"
    try:
        data = _get_json(url)
        return (data.get("esearchresult") or {}).get("idlist") or []
    except Exception:
        return []


def pubmed_fetch(pmids: list[str]) -> list[dict[str, Any]]:
    """Pull abstract text for a list of PMIDs."""
    if not pmids:
        return []
    q = urllib.parse.urlencode({
        "db": "pubmed", "id": ",".join(pmids),
        "rettype": "abstract", "retmode": "xml",
    })
    url = f"https://eutils.ncbi.nlm.nih.gov/entrez/eutils/efetch.fcgi?{q}"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=15) as resp:
            xml = resp.read().decode(errors="replace")
        # Minimal XML → dict (avoid extra deps). Extract title + abstract text.
        articles: list[dict[str, Any]] = []
        import re
        for m in re.finditer(
            r"<PubmedArticle>(.*?)</PubmedArticle>", xml, re.S
        ):
            block = m.group(1)
            pmid_m = re.search(r"<PMID[^>]*>(\d+)</PMID>", block)
            title_m = re.search(r"<ArticleTitle>(.*?)</ArticleTitle>", block, re.S)
            abs_m = re.search(r"<Abstract>(.*?)</Abstract>", block, re.S)
            articles.append({
                "pmid": pmid_m.group(1) if pmid_m else None,
                "title": re.sub(r"<[^>]+>", "", title_m.group(1)).strip()
                         if title_m else None,
                "abstract": re.sub(r"<[^>]+>", " ", abs_m.group(1)).strip()[:1200]
                            if abs_m else "",
            })
        return articles
    except Exception:
        return []
