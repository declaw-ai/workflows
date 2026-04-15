"""Synthetic patient data for workflow demos. NOT real PHI."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Patient:
    id: str
    name: str
    dob: str
    sex: str
    mrn: str
    member_id: str
    payer: str
    diagnoses: list[str] = field(default_factory=list)
    medications: list[str] = field(default_factory=list)
    labs: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


PATIENTS: dict[str, Patient] = {
    "p-001": Patient(
        id="p-001",
        name="Jordan Rivera",
        dob="1971-04-12",
        sex="F",
        mrn="MRN-44218",
        member_id="BCBS-7782341",
        payer="BlueCross WellCare",
        diagnoses=["E11.9 Type 2 diabetes mellitus", "I10 Essential hypertension"],
        medications=["Metformin 1000mg BID", "Lisinopril 20mg QD"],
        labs=[
            {"loinc": "4548-4", "name": "Hemoglobin A1c", "value": 9.2, "unit": "%", "ref": "<7.0"},
            {"loinc": "2160-0", "name": "Creatinine", "value": 1.1, "unit": "mg/dL", "ref": "0.6-1.2"},
        ],
        notes=[
            "55 y/o F with poorly controlled T2DM despite metformin and lifestyle changes. "
            "A1c trending up over 6 months (8.1 -> 9.2). Discussed adding GLP-1 agonist; "
            "patient interested in semaglutide. BMI 34. No retinopathy on last screening.",
        ],
    ),
    "p-002": Patient(
        id="p-002",
        name="Sam Okafor",
        dob="1958-11-03",
        sex="M",
        mrn="MRN-22904",
        member_id="UHC-9912047",
        payer="UnitedHealthcare",
        diagnoses=["C61 Prostate adenocarcinoma", "Z85.46 Hx prostate cancer"],
        medications=["Leuprolide 22.5mg q3mo"],
        labs=[
            {"loinc": "2857-1", "name": "PSA", "value": 12.4, "unit": "ng/mL", "ref": "<4.0"},
        ],
        notes=[
            "67 y/o M with biochemical recurrence of prostate adenocarcinoma post-RP in 2019. "
            "PSA rising on ADT. Considering enrollment in PSMA-targeted radioligand trial.",
        ],
    ),
    "p-003": Patient(
        id="p-003",
        name="Mei Tanaka",
        dob="1990-08-22",
        sex="F",
        mrn="MRN-71033",
        member_id="AETNA-3340912",
        payer="Aetna",
        diagnoses=["J45.40 Moderate persistent asthma"],
        medications=["Fluticasone/salmeterol 250/50 BID", "Albuterol PRN"],
        labs=[
            {"loinc": "26464-8", "name": "WBC", "value": 6.8, "unit": "10^3/uL", "ref": "4.5-11"},
            {"loinc": "718-7", "name": "Hemoglobin", "value": 13.1, "unit": "g/dL", "ref": "12-16"},
        ],
        notes=[
            "35 y/o F with moderate persistent asthma, three exacerbations in past 12mo "
            "requiring oral steroids. Eosinophil count 480. Considering biologic step-up.",
        ],
    ),
}


PAYER_POLICIES: dict[str, dict[str, Any]] = {
    "semaglutide_t2dm": {
        "payers": ["BlueCross WellCare", "UnitedHealthcare", "Aetna"],
        "criteria": [
            "Documented T2DM (E11.x)",
            "A1c >= 7.0% within last 90 days",
            "Trial of metformin >= 90 days OR contraindication",
            "BMI >= 27 OR cardiovascular comorbidity",
        ],
        "documentation_required": ["Recent A1c", "Med list", "BMI"],
    },
    "psma_radioligand": {
        "payers": ["UnitedHealthcare"],
        "criteria": [
            "Histologically confirmed metastatic castration-resistant prostate cancer",
            "PSMA-positive imaging",
            "Prior ARSI therapy",
        ],
        "documentation_required": ["Pathology report", "PSMA PET", "Treatment history"],
    },
    "mepolizumab_asthma": {
        "payers": ["Aetna", "BlueCross WellCare"],
        "criteria": [
            "Severe eosinophilic asthma",
            "Eosinophils >= 150 cells/uL",
            ">= 2 exacerbations requiring systemic steroids in past 12 months",
            "On high-dose ICS + LABA",
        ],
        "documentation_required": ["Eosinophil count", "Exacerbation history", "Current regimen"],
    },
}


CLINICAL_TRIALS: list[dict[str, Any]] = [
    {
        "id": "NCT05000001",
        "title": "PSMA-617 vs Standard of Care in mCRPC",
        "inclusion": [
            "Histologically confirmed prostate adenocarcinoma",
            "Castration-resistant disease",
            "PSMA-positive lesions",
            "Age >= 18",
            "ECOG <= 2",
        ],
        "exclusion": ["Prior PSMA-targeted therapy", "Active second malignancy"],
        "site": "Memorial Hospital, Bldg C",
    },
    {
        "id": "NCT05000002",
        "title": "Tirzepatide vs Semaglutide in T2DM with Obesity",
        "inclusion": [
            "Type 2 diabetes mellitus",
            "A1c 7.5-11.0%",
            "BMI >= 30",
            "Stable metformin >= 12 weeks",
        ],
        "exclusion": ["History of pancreatitis", "MEN-2", "Prior GLP-1 within 6mo"],
        "site": "Endocrine Clinic",
    },
    {
        "id": "NCT05000003",
        "title": "Anti-IL5R for Severe Eosinophilic Asthma",
        "inclusion": [
            "Severe asthma per GINA",
            "Eosinophils >= 300 cells/uL",
            ">= 2 exacerbations in past 12mo",
        ],
        "exclusion": ["Active smoker", "Pregnancy"],
        "site": "Pulmonology",
    },
]


PAYER_DENIAL_PATTERNS = {
    "missing_a1c": "Recent HbA1c not documented",
    "no_metformin_trial": "No documented trial of metformin",
    "bmi_not_documented": "BMI not in chart",
    "missing_pathology": "Pathology report not attached",
}
