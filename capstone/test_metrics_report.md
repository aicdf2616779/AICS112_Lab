# AICS112 Test and Metrics Report

**Project:** AI-SOAR Incident Triage and Safe Response  
**Environment:** SavannaPay Synthetic Cyber-Range  
**Version:** 1.0  
**Owner:** AICS112 Student Analyst  
**Execution mode:** Offline / dry-run only

## 1. Purpose

This report documents software testing, safety-control verification, evaluation metrics, and observed execution characteristics for the AICS112 AI-SOAR pipeline.

Testing was performed using supplied synthetic training data and the blind capstone dataset. Training evaluation metrics are reported separately from blind-capstone observations because the blind dataset does not provide student-accessible ground truth.

## 2. Unit Test Results

The project contains seven automated unit tests.

Command executed:

    pytest -q

Observed result:

    7 passed in 0.04s

| Test ID | Test | Expected Result | Actual Result | Pass |
|---|---|---|---|---|
| T-01 | Timestamp and field normalization | Convert timezone-aware timestamps to UTC, normalize fields, bound severity | Correct UTC conversion and normalization observed | PASS |
| T-02 | Naive timestamp rejection | Reject timestamps without timezone information | ValueError raised | PASS |
| T-03 | Event enrichment and IOC matching | Add asset/identity context and identify supplied IOC | Context and IOC match added | PASS |
| T-04 | Explainable risk scoring | Produce score with contributing features and weights | Score and explanation generated | PASS |
| T-05 | Prompt-injection handling | Detect suspicious instruction text and limit cleaned text | Injection flag generated and text length constrained | PASS |
| T-06 | Severity boundaries | Map defined score boundaries to severity bands | Low, medium, high and critical boundaries verified | PASS |
| T-07 | Audit hash chaining | Link consecutive records through previous hash and unique record hash | Chain linkage verified | PASS |

Overall automated test result: **7/7 passed**.

## 3. Negative and Safety Tests

Negative and safety-oriented behavior was tested through:

- rejection of timezone-naive timestamps;
- severity boundary testing;
- prompt-injection detection in untrusted evidence text;
- hash-chain linkage verification;
- explicit approval gates for high-impact response actions.

These controls are intended to reduce unsafe automation rather than prove complete security.

## 4. Auditability Verification

The blind capstone execution generated an audit log at:

    output/capstone_run/audit_log.jsonl

Observed results:

- Audit records: 19
- Audit chain: VALID
- Records with `dry_run=true`: 19/19
- Simulated actions: 15
- Awaiting-approval actions: 4

The four high-impact actions requiring approval were:

- SOAR-0005 — isolate endpoint
- SOAR-0005 — disable identity
- SOAR-0006 — isolate endpoint
- SOAR-0006 — disable identity

No approval token was used during the blind capstone run.

## 5. Training Dataset Evaluation

The supplied training dataset was evaluated separately using its provided ground-truth labels.

Observed results:

- TP: 8
- FP: 0
- TN: 4
- FN: 0
- Precision: 1.00
- Recall: 1.00
- F1: 1.00

These measurements describe performance on the supplied synthetic training dataset only.

They must not be interpreted as:

- real-world model performance;
- production performance;
- blind-capstone performance;
- evidence of an actual incident count.

## 6. Blind Capstone Metrics

The blind capstone dataset contains no student-accessible ground truth. Therefore precision, recall, F1, and hidden-incident-count comparisons are not reported.

Observed pipeline output:

- Candidate incidents: 9
- Low: 6
- High: 1
- Critical: 2

Highest pipeline risk scores:

| Incident | Risk score | Severity |
|---|---:|---|
| SOAR-0006 | 97 | Critical |
| SOAR-0005 | 91 | Critical |
| SOAR-0009 | 83 | High |

These are descriptive outputs of the student's pipeline and are not verified truth labels.

## 7. Source Participation

The blind run showed the following source participation among candidate incidents:

| Source | Candidate participation |
|---|---:|
| Endpoint | 6 |
| Identity | 3 |
| Network | 3 |
| Email | 3 |
| Proxy | 1 |

Source counts are descriptive pipeline results and do not represent ground truth.

## 8. Response Safety

The pipeline defines high-impact actions as approval-required operations.

High-impact actions include:

- `isolate_endpoint`
- `disable_identity`

During the blind run:

- high-impact actions remained `awaiting_approval`;
- all actions remained dry-run;
- no production account or endpoint was modified;
- no external infrastructure was contacted.

This demonstrates that a high risk score does not independently authorize consequential response.

## 9. Explainability

The scoring system records:

- feature values;
- feature weights;
- logit;
- probability-like model output;
- maximum event severity;
- severity baseline;
- model/severity weighting.

The output is therefore reviewable by an analyst rather than being presented as an unexplained classification.

Probability-like values are not treated as calibrated proof of compromise.

## 10. Latency and Reproducibility Assumptions

The measured unit-test execution time was approximately 0.04 seconds for seven tests in the current Kali virtual environment.

This is a test-suite execution measurement, not a production pipeline latency benchmark.

Production latency would depend on:

- event volume;
- enrichment size;
- storage performance;
- CPU and memory resources;
- network or API dependencies if a future implementation introduced them;
- analyst approval delays.

The current assessment intentionally avoids external services and therefore does not provide production API latency measurements.

## 11. Limitations

Important limitations include:

- synthetic data may not represent production telemetry;
- blind-capstone ground truth is unavailable to the student;
- training metrics cannot be generalized to production;
- correlation can produce false joins;
- approved administrative activity may resemble malicious behavior;
- blocked or quarantined events can still receive elevated scores;
- supplied threat intelligence is limited;
- probability-like outputs are not calibrated evidence;
- seven unit tests do not constitute exhaustive security testing.

## 12. Conclusion

The current implementation passed all seven automated unit tests.

The blind capstone run also demonstrated the intended safety controls: audit records were hash chained, all actions remained dry-run, and high-impact response actions remained approval-gated.

The available training metrics provide a controlled evaluation of the supplied training dataset. Because the capstone dataset is blind, its candidate incidents and risk scores are reported only as pipeline observations rather than verified incident labels.

Further validation would be required before any production deployment.
