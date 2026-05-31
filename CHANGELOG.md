# Changelog

## 1.0.0-prod — 2026-05-31

- Hardened to v1.0-prod per squad doctrine; member of the DefenseTech vertical 6-pack.
- Spec-component repo (no Pages deploy required); AGPL-3.0-or-later, synthetic example data only.
- Pulse universe entry not applicable (no custom subdomain).



## [0.1] — 2026-05-30

### Added

- Initial schema + verifier + canonical example.
- 18-kind enum covering: rfp-requirement-analyzed, rfp-response-draft-generated, technical-data-package-analyzed, weapon-system-design-trade-evaluated, threat-intel-indicator-triaged, contract-vehicle-bid-optimized, itar-ear-screening-performed, deemed-export-flagged, cmmc-poam-update-recommended, cmmc-l2-l3-readiness-assessment-produced, cui-spillage-detected, cui-distribution-statement-applied, classified-inference-performed-cleared-environment, dfars-cyber-incident-flagged, dfars-cyber-incident-report-filed, foreign-person-access-attempt-evaluated, security-clearance-access-decision-recommended, deletion-requested.
- **9-value `cui_categorization` taxonomy**: PUBLIC · CUI-BASIC · CUI-SPECIFIED · CUI-SPECIFIED-NOFORN · CONTROLLED-NOFORN · CLASSIFIED-CONFIDENTIAL · CLASSIFIED-SECRET · CLASSIFIED-TOP-SECRET · SCI. Per CUI Notice 2020-04 + E.O. 13526 + ICD 705.
- **4-value `export_control_status` taxonomy**: ITAR · EAR-CCL-RESTRICTED · EAR-99 · NOT-EXPORT-CONTROLLED.
- **5-value `foreign_person_access_restriction` taxonomy**: US-PERSON-ONLY · AUTHORIZED-FOREIGN-PERSON-WITH-LICENSE · FIVE-EYES-ONLY · NATO-PLUS-ONLY · NO-RESTRICTION.
- **3-axis design innovation** — all three above fields REQUIRED on every event. First Suite audit-stream with 3-dimensional first-class taxonomy.
- 21-value `regulatory_basis` enum spanning DFARS 252.204-7012/7019/7020/7021, CMMC 2.0 L1/L2/L3, NIST SP 800-171/172, ITAR, EAR, EAR deemed export, E.O. 13526, ICD 705, DoDI 5230.24, CUI Notice 2020-04, NISPOM, FAR 52.204-21, False Claims Act.
- 10-scheme `subject_ref` taxonomy: CAGE code / DUNS / contract vehicle / RFP solicitation / weapon system program / TDP / threat indicator / CMMC assessment / facility clearance / personnel clearance — all tokenized.
- 15-type `resource.type` enum + 8-value `agent.human_user_clearance_level_tokenized` (UNCLASSIFIED / SECRET / TOP-SECRET / TS-SCI) + DDTC export license number tokenized field for foreign-person access events.
- 3 invariants enforced by `src/verify.mjs`:
  - **#1: CUI distribution-statement** — every CUI-SPECIFIED+ event MUST carry a `distribution_statement` block per DoDI 5230.24.
  - **#2: Export-control gating** — every ITAR event MUST verify `human_user_us_person_status` (and DDTC license number on AUTHORIZED-FOREIGN-PERSON).
  - **#3: DFARS 72-hour cyber incident reporting** — second Suite verifier enforcing a regulatory wall-clock numerically.
- Canonical example: Stratos Aerospace × VendorD GuardianAI v3.x — 7-event trajectory exercising CUI-Basic / CUI-Specified-NoForn / ITAR / foreign-person blocked access / DFARS 72-hour reporting / CMMC L2 POA&M.
- CI workflow.

### Not yet

- TOP-SECRET / SCI compartmented program example (would require fictional program designations).
- Pure EAR-only flow (everything seeded is ITAR-touching).
- Successful AUTHORIZED-FOREIGN-PERSON flow with valid DDTC license (current example shows blocked attempt).
- Multi-CAGE-code joint-venture example.
- ed25519 `signature` field example.