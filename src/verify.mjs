#!/usr/bin/env node
// verify.mjs — Defense Decision Record Audit Stream verifier.
//
// Verifies:
//   1. Schema validation against schema/defense-decision-event.schema.json
//   2. Hash chain integrity (canonical-JSON SHA-256, prev_hash chained)
//   3. **CUI distribution-statement invariant**: every event with
//      resource.cui_categorization at CUI-SPECIFIED or higher MUST carry
//      a distribution_statement block per DoDI 5230.24.
//   4. **Export-control gating invariant**: every event with
//      resource.export_control_status = ITAR MUST set
//      agent.human_user_us_person_status to US-PERSON-VERIFIED OR
//      AUTHORIZED-FOREIGN-PERSON-WITH-LICENSE (with ddtc_export_license_number_tokenized).
//   5. **DFARS 72-hour incident reporting invariant**: any kind=defensetech.
//      dfars.cyber-incident-flagged event MUST include dfars_cyber_incident_report_ref
//      AND filed_at must be within 72 hours of the event timestamp (DFARS
//      252.204-7012(c)(1)(ii) reporting window to dibnet.dod.mil).
//
// Exit codes:
//   0 — all events valid
//   1 — schema failed
//   2 — chain failed
//   3 — CUI distribution-statement invariant violated
//   4 — Export-control gating invariant violated
//   5 — DFARS 72-hour reporting invariant violated
//   6 — usage / IO error

import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { Ajv2020 } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const ZERO_HASH = "0".repeat(64);
const SEVENTY_TWO_HOURS_MS = 72 * 60 * 60 * 1000;

// CUI tiers that REQUIRE a distribution statement per DoDI 5230.24
const DIST_STATEMENT_REQUIRED_TIERS = new Set([
  "CUI-SPECIFIED",
  "CUI-SPECIFIED-NOFORN",
  "CONTROLLED-NOFORN",
  "CLASSIFIED-CONFIDENTIAL",
  "CLASSIFIED-SECRET",
  "CLASSIFIED-TOP-SECRET",
  "SCI"
]);

function canonicalize(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(value[k])).join(",") + "}";
}
const sha256 = (s) => createHash("sha256").update(s, "utf8").digest("hex");

function loadStream(path) {
  return readFileSync(path, "utf8").trim().split("\n").map((line, i) => {
    try { return JSON.parse(line); } catch (e) {
      throw new Error(`line ${i + 1}: invalid JSON — ${e.message}`);
    }
  });
}

function main() {
  const path = process.argv[2];
  if (!path) { console.error("usage: verify.mjs <stream.ndjson>"); process.exit(6); }

  let events;
  try { events = loadStream(path); }
  catch (e) { console.error(`load error: ${e.message}`); process.exit(6); }

  const schemaPath = new URL("../schema/defense-decision-event.schema.json", import.meta.url);
  const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  addFormats(ajv);
  const validate = ajv.compile(schema);

  // Schema
  for (const [i, event] of events.entries()) {
    if (!validate(event)) {
      console.error(`event[${i}] (${event.event_id}) schema fail:`);
      for (const e of validate.errors || []) console.error(`  ${e.instancePath} ${e.message}`);
      process.exit(1);
    }
  }

  // Chain
  let prev = ZERO_HASH;
  for (const [i, event] of events.entries()) {
    if (event.prev_hash !== prev) {
      console.error(`event[${i}] (${event.event_id}) chain: prev_hash=${event.prev_hash} expected=${prev}`);
      process.exit(2);
    }
    const { hash, ...body } = event;
    const expected = sha256(canonicalize(body));
    if (hash !== expected) {
      console.error(`event[${i}] (${event.event_id}) chain: hash=${hash} recomputed=${expected}`);
      process.exit(2);
    }
    prev = event.hash;
  }

  // Invariant 3: CUI distribution-statement REQUIRED on CUI-Specified+
  for (const [i, event] of events.entries()) {
    const tier = event.resource?.cui_categorization;
    if (DIST_STATEMENT_REQUIRED_TIERS.has(tier)) {
      if (!event.distribution_statement?.statement_letter || !event.distribution_statement?.applied_at) {
        console.error(`event[${i}] (${event.event_id}) cui-distribution-statement: tier=${tier} requires distribution_statement block per DoDI 5230.24`);
        process.exit(3);
      }
    }
  }

  // Invariant 4: Export-control gating on ITAR
  for (const [i, event] of events.entries()) {
    if (event.resource?.export_control_status === "ITAR") {
      const usp = event.agent?.human_user_us_person_status;
      if (!usp || usp === "NOT-VERIFIED") {
        console.error(`event[${i}] (${event.event_id}) export-control: ITAR resource requires agent.human_user_us_person_status (US-PERSON-VERIFIED or AUTHORIZED-FOREIGN-PERSON-WITH-LICENSE), got "${usp || "missing"}"`);
        process.exit(4);
      }
      if (usp === "AUTHORIZED-FOREIGN-PERSON-WITH-LICENSE" && !event.agent?.ddtc_export_license_number_tokenized) {
        console.error(`event[${i}] (${event.event_id}) export-control: AUTHORIZED-FOREIGN-PERSON requires agent.ddtc_export_license_number_tokenized`);
        process.exit(4);
      }
    }
  }

  // Invariant 5: DFARS 72-hour incident reporting clock
  for (const [i, event] of events.entries()) {
    if (event.kind === "defensetech.dfars.cyber-incident-flagged") {
      const ref = event.dfars_cyber_incident_report_ref;
      if (!ref?.report_id || !ref?.filed_at || !ref?.dibnet_dod_mil_url) {
        console.error(`event[${i}] (${event.event_id}) dfars-72-hour: requires dfars_cyber_incident_report_ref with report_id + filed_at + dibnet_dod_mil_url`);
        process.exit(5);
      }
      const eventAt = Date.parse(event.timestamp);
      const filedAt = Date.parse(ref.filed_at);
      if (!Number.isFinite(eventAt) || !Number.isFinite(filedAt)) {
        console.error(`event[${i}] (${event.event_id}) dfars-72-hour: unparseable timestamp(s)`);
        process.exit(5);
      }
      if (filedAt - eventAt > SEVENTY_TWO_HOURS_MS) {
        console.error(`event[${i}] (${event.event_id}) dfars-72-hour: filed_at ${ref.filed_at} is more than 72h after event timestamp ${event.timestamp} (DFARS 252.204-7012(c)(1)(ii) window)`);
        process.exit(5);
      }
    }
  }

  console.log(`OK · ${events.length} events · schema ✓ · chain ✓ · cui-distribution-statement ✓ · export-control-gating ✓ · dfars-72-hour-reporting ✓`);
}

main();
