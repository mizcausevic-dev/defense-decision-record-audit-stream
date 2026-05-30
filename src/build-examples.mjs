// build-examples.mjs — Builds the canonical hash-chained example stream.
// Stratos Aerospace × VendorD GuardianAI v3.x — a 7-event defense-contractor
// trajectory exercising CUI-Basic / CUI-Specified-NoForn / ITAR / foreign-
// person access controls + DFARS 72-hour cyber incident reporting + CMMC
// L2 POA&M update.

import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = resolve(HERE, "../examples/stratos-guardianai-2026q4");
const OUT_STREAM = resolve(HERE, "../examples/stratos-guardianai-2026q4-stream.ndjson");
const ZERO_HASH = "0".repeat(64);

function canonicalize(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(value[k])).join(",") + "}";
}
const sha256 = (s) => createHash("sha256").update(s, "utf8").digest("hex");

const AGENT_BASE = {
  ai_tool_card_url:     "https://vendord-guardianai.example/.well-known/ai-tool-cards/guardianai-3.x.json",
  ai_decision_card_url: "https://stratos-aerospace.example/.well-known/decisions/STRATOS-DEC-2026-DEF-0084.json"
};
const DECISION_CARD = AGENT_BASE.ai_decision_card_url;

let prevHash = ZERO_HASH;
function buildEvent(partial) {
  const event = { ...partial, prev_hash: prevHash };
  const { hash: _h, ...body } = event;
  const eventHash = sha256(canonicalize(body));
  event.hash = eventHash;
  prevHash = eventHash;
  return event;
}

const events = [
  // 1. RFP requirement analysis — CUI-Basic, no export control, US-person-only
  buildEvent({
    event_id: "0190dt-0001",
    timestamp: "2026-11-03T14:00:00Z",
    kind: "defensetech.rfp.requirement-analyzed",
    source: "stratos-cui-enclave-prod",
    subject_ref: { scheme: "rfp-solicitation-number-tokenized", value: "tok_rfp_AF_RFP_2027_001" },
    resource: { type: "rfp-solicitation-document", id_tokenized: "tok_res_rfp_a1", cui_categorization: "CUI-BASIC", export_control_status: "NOT-EXPORT-CONTROLLED", foreign_person_access_restriction: "US-PERSON-ONLY" },
    action: "read",
    outcome: { status: "success", recommendation: "advisory-only" },
    agent: { ...AGENT_BASE, human_user_clearance_level_tokenized: "tok_clr_UNCLASSIFIED", human_user_us_person_status: "US-PERSON-VERIFIED" },
    regulatory_basis: ["dfars-252-204-7012-cdi-safeguarding", "nist-sp-800-171-cui-protection", "cui-notice-2020-04-implementation"],
    decision_card_ref: DECISION_CARD
  }),

  // 2. Export control screening on weapon-system technical data — ITAR, US-person-only
  buildEvent({
    event_id: "0190dt-0002",
    timestamp: "2026-11-03T15:30:00Z",
    kind: "defensetech.export-control.itar-ear-screening-performed",
    source: "stratos-export-control-prod",
    subject_ref: { scheme: "technical-data-package-id-tokenized", value: "tok_tdp_F35_subsystem_22" },
    resource: { type: "technical-data-package", id_tokenized: "tok_res_tdp_b2", cui_categorization: "CUI-SPECIFIED-NOFORN", export_control_status: "ITAR", foreign_person_access_restriction: "US-PERSON-ONLY" },
    action: "search",
    outcome: { status: "success", recommendation: "supervisor-review-required" },
    agent: { ...AGENT_BASE, human_user_clearance_level_tokenized: "tok_clr_SECRET", human_user_us_person_status: "US-PERSON-VERIFIED" },
    regulatory_basis: ["itar-22-cfr-120-130", "ear-deemed-export-22-cfr-120-50", "nist-sp-800-172-enhanced-security-requirements"],
    distribution_statement: { statement_letter: "D", applied_at: "2026-11-03T15:30:00Z", rationale: "Distribution authorized to DoD + DoD contractors only" },
    decision_card_ref: DECISION_CARD
  }),

  // 3. Weapon-system design trade evaluation — CUI-Specified, NoForn, FSO co-sign on production-ready
  buildEvent({
    event_id: "0190dt-0003",
    timestamp: "2026-11-03T16:45:00Z",
    kind: "defensetech.weapon-system.design-trade-evaluated",
    source: "stratos-design-analytics-prod",
    subject_ref: { scheme: "weapon-system-program-id-tokenized", value: "tok_prog_NextGen_AAM_2027" },
    resource: { type: "weapon-system-design-document", id_tokenized: "tok_res_wsd_c3", cui_categorization: "CUI-SPECIFIED-NOFORN", export_control_status: "ITAR", foreign_person_access_restriction: "US-PERSON-ONLY" },
    action: "generate",
    outcome: { status: "success", recommendation: "halt-and-escalate-to-empowered-official" },
    agent: { ...AGENT_BASE, human_user_clearance_level_tokenized: "tok_clr_SECRET", human_user_us_person_status: "US-PERSON-VERIFIED", fso_session_id_tokenized: "tok_fso_session_5e7" },
    regulatory_basis: ["itar-22-cfr-120-130", "nist-sp-800-172-enhanced-security-requirements", "cui-notice-2020-04-implementation"],
    distribution_statement: { statement_letter: "C", applied_at: "2026-11-03T16:45:00Z", rationale: "Distribution authorized to US Government agencies + their contractors only" },
    decision_card_ref: DECISION_CARD
  }),

  // 4. Foreign-person access attempt evaluated — blocked. Distribution
  // statement inherits from the CUI-Specified-NoForn source the access
  // was attempted against (per DoDI 5230.24, any handling event on
  // Specified+ tier carries the statement).
  buildEvent({
    event_id: "0190dt-0004",
    timestamp: "2026-11-03T17:12:00Z",
    kind: "defensetech.foreign-person.access-attempt-evaluated",
    source: "stratos-iam-prod",
    subject_ref: { scheme: "personnel-clearance-id-tokenized", value: "tok_clr_personnel_4a9" },
    resource: { type: "foreign-person-access-attempt-log", id_tokenized: "tok_res_fpa_d4", cui_categorization: "CUI-SPECIFIED-NOFORN", export_control_status: "ITAR", foreign_person_access_restriction: "US-PERSON-ONLY" },
    action: "stamp",
    outcome: { status: "blocked-by-foreign-person-restriction", recommendation: "halt-and-escalate-to-empowered-official" },
    agent: { ...AGENT_BASE, human_user_clearance_level_tokenized: "tok_clr_UNCLASSIFIED", human_user_us_person_status: "AUTHORIZED-FOREIGN-PERSON-WITH-LICENSE", ddtc_export_license_number_tokenized: "tok_ddtc_lic_9c1" },
    regulatory_basis: ["itar-22-cfr-120-130", "ear-deemed-export-22-cfr-120-50"],
    distribution_statement: { statement_letter: "C", applied_at: "2026-11-03T17:12:00Z", rationale: "Inherited from source CUI-Specified-NoForn resource — distribution to US Government agencies + their contractors only" },
    decision_card_ref: DECISION_CARD
  }),

  // 5. DFARS cyber incident flagged (CUI spillage detected)
  buildEvent({
    event_id: "0190dt-0005",
    timestamp: "2026-11-03T18:00:00Z",
    kind: "defensetech.dfars.cyber-incident-flagged",
    source: "stratos-soc-prod",
    subject_ref: { scheme: "cage-code-tokenized", value: "tok_cage_STRATOS_AERO_1A2B3" },
    resource: { type: "cui-spillage-event-log", id_tokenized: "tok_res_spillage_e5", cui_categorization: "CUI-BASIC", export_control_status: "NOT-EXPORT-CONTROLLED", foreign_person_access_restriction: "US-PERSON-ONLY" },
    action: "stamp",
    outcome: { status: "serious-failure", recommendation: "halt-and-escalate-to-fso" },
    agent: { ...AGENT_BASE, human_user_clearance_level_tokenized: "tok_clr_SECRET", human_user_us_person_status: "US-PERSON-VERIFIED" },
    regulatory_basis: ["dfars-252-204-7012-cyber-incident-reporting", "nist-sp-800-171-cui-protection"],
    dfars_cyber_incident_report_ref: {
      report_id: "STRATOS-DFARS-2026-0011",
      filed_at: "2026-11-04T15:30:00Z",
      dibnet_dod_mil_url: "https://dibnet.dod.mil/reports/STRATOS-DFARS-2026-0011"
    },
    decision_card_ref: DECISION_CARD
  }),

  // 6. CMMC L2 POA&M update — recommendation produced
  buildEvent({
    event_id: "0190dt-0006",
    timestamp: "2026-11-04T10:00:00Z",
    kind: "defensetech.cmmc.poam-update-recommended",
    source: "stratos-cmmc-prod",
    subject_ref: { scheme: "cmmc-assessment-id-tokenized", value: "tok_cmmc_STRATOS_L2_2026" },
    resource: { type: "cmmc-poam-record", id_tokenized: "tok_res_poam_f6", cui_categorization: "CUI-BASIC", export_control_status: "NOT-EXPORT-CONTROLLED", foreign_person_access_restriction: "US-PERSON-ONLY" },
    action: "generate",
    outcome: { status: "success", recommendation: "supervisor-review-required" },
    agent: { ...AGENT_BASE, human_user_clearance_level_tokenized: "tok_clr_UNCLASSIFIED", human_user_us_person_status: "US-PERSON-VERIFIED" },
    regulatory_basis: ["cmmc-2-0-level-2-c3pao-assessment", "dfars-252-204-7021-cmmc-assessment-level-2-or-3", "nist-sp-800-171-cui-protection"],
    decision_card_ref: DECISION_CARD
  }),

  // 7. RFP response draft generated — final, US-person-only
  buildEvent({
    event_id: "0190dt-0007",
    timestamp: "2026-11-04T16:00:00Z",
    kind: "defensetech.rfp.response-draft-generated",
    source: "stratos-proposal-prod",
    subject_ref: { scheme: "rfp-solicitation-number-tokenized", value: "tok_rfp_AF_RFP_2027_001" },
    resource: { type: "rfp-response-draft", id_tokenized: "tok_res_rfp_resp_g7", cui_categorization: "CUI-BASIC", export_control_status: "NOT-EXPORT-CONTROLLED", foreign_person_access_restriction: "US-PERSON-ONLY" },
    action: "generate",
    outcome: { status: "success", recommendation: "supervisor-review-required" },
    agent: { ...AGENT_BASE, human_user_clearance_level_tokenized: "tok_clr_UNCLASSIFIED", human_user_us_person_status: "US-PERSON-VERIFIED" },
    regulatory_basis: ["dfars-252-204-7012-cdi-safeguarding", "far-52-204-21-basic-safeguarding", "false-claims-act-31-usc-3729"],
    decision_card_ref: DECISION_CARD
  })
];

mkdirSync(OUT_DIR, { recursive: true });
mkdirSync(dirname(OUT_STREAM), { recursive: true });
for (const event of events) {
  writeFileSync(resolve(OUT_DIR, `${event.event_id}.json`), JSON.stringify(event, null, 2) + "\n", "utf8");
}
writeFileSync(OUT_STREAM, events.map((e) => JSON.stringify(e)).join("\n") + "\n", "utf8");
console.log(`built ${events.length} events → ${OUT_STREAM}`);
