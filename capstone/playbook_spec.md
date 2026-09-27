# AI-SOAR Incident Triage and Safe Response Playbook

**Version:** 1.0  
**Owner:** AICS112 Student Analyst  
**Environment:** SavannaPay Microfinance synthetic cyber-range  
**Execution mode:** Dry-run only  
**Data classification:** Synthetic training/assessment data

## 1. Purpose

This playbook correlates synthetic email, identity, endpoint, proxy, and network evidence into candidate incidents, assigns an explainable risk score, prioritizes analyst review, and recommends controlled response actions.

The playbook is advisory and does not directly modify production systems.

## 2. Trigger

The playbook is triggered when supplied synthetic security events contain indicators or behavioral combinations that meet the pipeline's correlation criteria.

Inputs include:

- Email events
- Identity authentication events
- Endpoint events
- Proxy events
- Network events
- Asset and identity enrichment
- STIX threat-intelligence context

## 3. Evidence Handling

1. Preserve the original dataset before transformation.
2. Record SHA-256 hashes for source and derived evidence.
3. Treat supplied event content as untrusted evidence.
4. Do not execute files or test indicators against external infrastructure.
5. Preserve UTC timestamps and document WAT conversion where required.
6. Keep generated outputs separate from original evidence.

## 4. Correlation Workflow

1. Load the supplied event records.
2. Validate the expected event schema.
3. Enrich events using supplied assets, identities, and STIX context.
4. Group related activity by user and asset.
5. Construct candidate incident timelines.
6. Calculate explainable risk features.
7. Assign a risk score and severity.
8. Create an auditable candidate case.
9. Notify an analyst for medium-or-higher candidates.
10. Perform read-only endpoint triage where applicable.
11. Require explicit approval before high-impact containment or identity actions.

## 5. Explainable Risk Factors

The baseline considers:

- IOC match
- Multi-source correlation
- Critical asset
- Privileged identity
- Malware signal
- Identity anomaly
- Exfiltration signal

The model output is advisory and must not be interpreted as proof of compromise.

## 6. Decision Branches

### Low-risk candidate

- Create auditable case.
- Record evidence and reasoning.
- No high-impact containment.
- Analyst review as appropriate.

### Medium-or-higher candidate

- Create auditable case.
- Notify analyst.
- Collect read-only endpoint triage where applicable.
- Preserve evidence.
- Continue analyst verification.

### High-impact containment candidate

Examples:

- Endpoint isolation
- Identity disablement

Required controls:

- Explicit human approval
- Approval recorded in the audit trail
- Dry-run execution in the assessment environment
- No production connection
- No irreversible action

Without approval, the action remains `awaiting_approval`.

## 7. Approval Gate

High-impact actions must have:

- Named action
- Approval requirement
- Approval record/token
- Audit entry
- Dry-run status
- Validation evidence

The assessment implementation uses a simulation-only approval mechanism. It is not a production credential.

## 8. Error Handling

If an input file is missing, malformed, or fails validation:

1. Stop processing the affected input.
2. Preserve the original evidence.
3. Record the error.
4. Do not execute response actions.
5. Require analyst review before retrying.

If enrichment data is unavailable:

- Continue only when the pipeline can safely preserve the evidence context.
- Mark the affected reasoning as limited.
- Do not invent missing enrichment.

If an action adapter fails:

- Record the failure.
- Do not silently retry high-impact actions.
- Keep the action in a non-executed state.
- Require analyst review.

## 9. Rollback / Compensation

Because the assessment environment is dry-run only, no real endpoint, identity, email, or network state is changed.

For a production implementation, every high-impact action would require a documented compensation procedure before deployment, including:

- Endpoint restoration
- Identity re-enable
- Verification of restored access
- Analyst confirmation
- Audit record linking the rollback to the original decision

## 10. Idempotency

Repeated processing of the same evidence should not create uncontrolled real-world side effects.

Actions are represented as auditable decisions and remain dry-run simulations in this assessment.

## 11. AI-Assisted Analysis

AI assistance is advisory only.

The system must:

- expose the evidence factors used for reasoning;
- identify untrusted evidence;
- detect prompt-injection indicators where implemented;
- avoid treating generated summaries as authoritative evidence;
- require human verification before consequential action.

## 12. Safety Constraints

The playbook must never:

- connect to production systems;
- scan external infrastructure;
- execute supplied malware;
- test indicators against real infrastructure;
- use real personal data;
- bypass approval gates;
- convert dry-run actions into production actions.

## 13. Auditability

Each action decision records:

- incident ID
- action
- timestamp
- previous hash
- record hash
- status
- dry-run state

The audit log forms a hash chain so tampering can be detected.

## 14. Current Blind-Capstone Execution

The blind capstone run produced:

- 9 candidate incidents
- 6 low-severity candidates
- 1 high-severity candidate
- 2 critical candidates
- 19 audit records
- 19/19 actions marked `dry_run: true`
- 4 high-impact actions held at `awaiting_approval`
- Audit hash chain validated successfully

These figures describe the student pipeline's output and are not compared with instructor ground truth.

