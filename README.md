# defense-decision-record-audit-stream

> **DefenseTech audit-stream Operator (Spec #1 of the DefenseTech 6-pack).** Hash-chained append-only ledger of which AI tool produced which defense-domain decision — RFP/RFI response, technical-data-package analysis, weapon-system design, threat-intel triage, contract-vehicle bid optimization, ITAR/EAR screening, CMMC POA&M update, CUI spillage detection, classified inference, foreign-person access evaluation — under which DFARS / CMMC / NIST 800-171/172 / ITAR / EAR / NISPOM / DoDI 5230.24 / FAR / FCA basis. **EVERY event carries explicit `cui_categorization` + `export_control_status` + `foreign_person_access_restriction`** — DefenseTech's first **3-axis** design innovation versus sibling-vertical audit-streams.

Part of the [Kinetic Gain Protocol Suite](https://suite.kineticgain.com).

> Status: v0.1 draft. Schema at [`schema/defense-decision-event.schema.json`](./schema/defense-decision-event.schema.json), canonical 7-event chain at [`examples/stratos-guardianai-2026q4-stream.ndjson`](./examples/stratos-guardianai-2026q4-stream.ndjson), verifier at [`src/verify.mjs`](./src/verify.mjs).

## Regulatory floor

- **DFARS 252.204-7012** — Safeguarding Covered Defense Information + 72-hour cyber incident reporting to `dibnet.dod.mil`
- **DFARS 252.204-7019 / 7020 / 7021** — NIST 800-171 self-assessment + CMMC certification + Level 2/3 assessment requirements
- **CMMC 2.0** — Levels 1 (self) / 2 (C3PAO) / 3 (DIBCAC); becoming sole-source-disqualifying in 2026 under 7021
- **NIST SP 800-171** (CUI protection in nonfederal systems) + **NIST SP 800-172** (enhanced security requirements for CMMC L3)
- **ITAR** (22 CFR 120-130) — International Traffic in Arms Regulations, DDTC licensing
- **EAR** (15 CFR 730-774) — Export Administration Regulations + deemed-export rule (22 CFR 120.50)
- **E.O. 13526** — Classified National Security Information + **ICD 705** SCIF physical-security standards
- **DoDI 5230.24** — Distribution Statements on Technical Documents (letters A through F + X)
- **CUI Notice 2020-04** — implementation of CUI Registry
- **NISPOM** (32 CFR 117) — National Industrial Security Program Operating Manual
- **FAR 52.204-21** — Basic Safeguarding of Covered Contractor Information Systems
- **False Claims Act** (31 USC 3729) — penalties for false certification of cybersecurity compliance (post-Aerojet Rocketdyne settlement)

## Canonical example

- **Buyer:** Stratos Aerospace — DIB Tier 2 defense contractor (representative of a CAGE-coded prime sub)
- **Vendor / AI system:** VendorD GuardianAI v3.x — defense-domain AI tool (RFP analytics + technical data package screening + CUI handling)

## Three invariants enforced by the verifier

1. **CUI distribution-statement invariant** — every event with `resource.cui_categorization` at CUI-SPECIFIED or higher MUST carry a `distribution_statement` block per DoDI 5230.24. The verifier rejects unfiled events.

2. **Export-control gating invariant** — every event with `resource.export_control_status = ITAR` MUST set `agent.human_user_us_person_status` to `US-PERSON-VERIFIED` OR `AUTHORIZED-FOREIGN-PERSON-WITH-LICENSE` (with `ddtc_export_license_number_tokenized`). Default `NOT-VERIFIED` is rejected.

3. **DFARS 72-hour incident reporting invariant** — any `defensetech.dfars.cyber-incident-flagged` event MUST include `dfars_cyber_incident_report_ref` with `report_id` + `filed_at` + `dibnet_dod_mil_url`, AND `filed_at` must be within **72 hours** of the event timestamp (DFARS 252.204-7012(c)(1)(ii) clock). This is the second Suite audit-stream invariant enforcing a regulatory wall-clock numerically (after EnergyTech's CIP-008 1-hour).

## Key design innovations vs sibling-vertical audit-streams

| Innovation | Why it's DefenseTech-specific |
| --- | --- |
| **Three first-class fields together** — `cui_categorization` + `export_control_status` + `foreign_person_access_restriction` REQUIRED on every event | First 3-axis taxonomy in the Suite (LegalTech was 1D `privilege_tier`, EnergyTech was 2D `bes_cyber_system_categorization` + `ot_it_boundary`). Defense regulators don't compose — DDTC doesn't care about CUI, DoD CIO doesn't care about EAR licenses, but the audit stream has to satisfy all three simultaneously. |
| `agent.human_user_us_person_status` REQUIRED on ITAR resources | 22 CFR 120.62 US-person definition is enforceable per-event, not per-session. The audit stream proves who looked at what. |
| `agent.fso_session_id_tokenized` for production-ready output on CLASSIFIED tiers | Facility Security Officer co-sign requirement encoded at audit-event layer. |
| `agent.ddtc_export_license_number_tokenized` for AUTHORIZED-FOREIGN-PERSON access | License number captured per-event, not just per-vendor — enables per-event compliance review by DDTC. |
| Outcome statuses `blocked-by-cui-categorization` / `-export-control` / `-foreign-person-restriction` / `-clearance-level` / `-cmmc-poam-open` | Five distinct blocking outcomes reflect five distinct enforcement regimes — most extensive blocking taxonomy in the Suite. |
| `distribution_statement` block with DoDI 5230.24 letter codes A-F + X | Encodes the DoD's own classification scheme for distribution restrictions — first Suite vertical with a distribution-classification field. |

## Verify

```bash
npm install
npm run build:examples   # builds the canonical 7-event chain
npm run verify           # validates schema + chain + 3 invariants
```

## Composes with

- [`cui-data-vault-contract-profile`](https://github.com/mizcausevic-dev/cui-data-vault-contract-profile) — Decision Card vault contract for CUI / classified / ITAR / EAR data
- [`cmmc-l2-l3-readiness-evidence-bundle`](https://github.com/mizcausevic-dev/cmmc-l2-l3-readiness-evidence-bundle) — readiness evidence bundle this stream supplies events to
- [`defense-ai-incident-card-profile`](https://github.com/mizcausevic-dev/defense-ai-incident-card-profile) — where any verifier failure (`status: "blocked-by-cui-categorization"` / DFARS 72-hour missed) becomes a published Incident Card
- [`dod-cmmc-disclosure-tracker`](https://github.com/mizcausevic-dev/dod-cmmc-disclosure-tracker) — DoD + CMMC AB + NIST + DDTC + BIS regulatory lifecycle context
- [`defense-contractor-bias-coverage-lab`](https://github.com/mizcausevic-dev/defense-contractor-bias-coverage-lab) — bias in DIB hiring / security-clearance access patterns / Equal Pay / VEVRAA veteran preference
- [`grid-decision-record-audit-stream`](https://github.com/mizcausevic-dev/grid-decision-record-audit-stream) — sibling-vertical audit-stream (EnergyTech, also wall-clock invariant model)
- [Kinetic Gain Protocol Suite](https://suite.kineticgain.com) — umbrella

## Compliance posture

Audit-stream **readiness scaffolding** for AI tools touching defense-domain decisions, CUI / classified / ITAR / EAR data, and CMMC L2/L3 contractor environments. **This does NOT constitute CMMC certification** (only a C3PAO or DIBCAC can issue that), **does NOT establish DFARS 252.204-7012 compliance**, **does NOT substitute for DDTC export-license review**, and **does NOT replace the contractor's NISPOM-required security program**. Per the standing public-language guardrail across the Suite — *readiness · evidence · posture · controls · scaffolding* — never "compliant" / "certified" without an external attestation specific to each regulatory regime.

## License

Spec text + JSON schemas + example documents + reference verifier: MIT.
