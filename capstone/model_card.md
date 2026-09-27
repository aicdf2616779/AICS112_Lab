# AI-SOAR Explainable Risk Model Card

**Model name:** Offline Explainable Baseline  
**Version:** 1.0  
**Owner:** AICS112 Student Analyst  
**Environment:** Synthetic SavannaPay cyber-range  
**Execution mode:** Dry-run / advisory only

## 1. Intended Use

The model supports analyst triage of correlated synthetic security events.

It is intended to:

- prioritize candidate incidents;
- provide an explainable risk score;
- identify contributing evidence factors;
- support analyst review;
- recommend safe next steps.

The model is not intended to make autonomous production containment decisions.

## 2. Prohibited Use

The model must not be used to:

- autonomously disable real user accounts;
- autonomously isolate production endpoints;
- execute malware;
- scan external infrastructure;
- test indicators against real systems;
- process real personal data in this assessment;
- replace human investigation or approval.

## 3. Inputs and Features

The baseline uses the following explainable features:

| Feature | Description |
|---|---|
| `ioc_match` | Indicator matches supplied threat-intelligence context |
| `multi_source` | Related activity appears across multiple telemetry sources |
| `critical_asset` | Asset context indicates critical importance |
| `privileged_identity` | Identity context indicates privileged access |
| `malware_signal` | Endpoint evidence contains a malware-related signal |
| `identity_anomaly` | Authentication behavior contains an anomaly |
| `exfil_signal` | Evidence indicates possible outbound data transfer |

The model also considers maximum observed event severity and a severity baseline.

## 4. Risk Calculation

The implementation combines an explainable model component with observed event severity.

The model records:

- feature values;
- feature weights;
- logit;
- probability-like model output;
- maximum observed severity;
- severity baseline;
- model weight;
- severity weight.

For the current implementation, the recorded weights are:

- Model component: 0.70
- Severity component: 0.30

The resulting risk score is used for prioritization.

## 5. Output and Threshold Behavior

The pipeline produces:

- risk score;
- severity;
- contributing features;
- evidence timeline;
- recommended actions.

Severity categories include:

- low
- medium
- high
- critical

The score is an analyst-prioritization signal, not proof that an incident occurred.

High-impact actions are never authorized solely by the score.

## 6. Evaluation

The supplied training dataset was evaluated separately from the blind capstone dataset.

Training evaluation produced:

- TP: 8
- FP: 0
- TN: 4
- FN: 0
- Precision: 1.00
- Recall: 1.00
- F1: 1.00

These results apply only to the supplied training dataset and must not be interpreted as real-world or blind-capstone performance.

The blind capstone dataset has no student-accessible ground truth. Therefore no precision, recall, F1, or hidden-incident-count comparison is claimed for the blind run.

## 7. Blind-Capstone Observation

The blind capstone run produced:

- 9 candidate incidents;
- 2 critical candidates;
- 1 high candidate;
- 6 low candidates.

The three highest risk scores were:

- SOAR-0006: 97
- SOAR-0005: 91
- SOAR-0009: 83

These are pipeline outputs and are not treated as verified truth labels.

## 8. Limitations and Bias

Potential limitations include:

- synthetic event distributions may not represent production environments;
- correlation by user and asset can create false joins;
- threat-intelligence context is limited to supplied enrichment;
- missing telemetry can reduce confidence;
- risk scores depend on the selected features and weights;
- probability-like outputs are not calibrated evidence of actual compromise;
- approved administrative activity can resemble malicious behavior;
- blocked or quarantined activity may be scored highly despite successful prevention.

Analysts must verify evidence before consequential action.

## 9. Security Controls

The implementation uses:

- dry-run-only execution;
- explicit approval gates;
- immutable-style hash chaining for audit records;
- evidence preservation;
- separation of source evidence and derived outputs;
- advisory-only AI assistance;
- untrusted evidence handling;
- prompt-injection flag reporting;
- no external infrastructure interaction.

## 10. Human Oversight

AI-generated analysis is advisory.

The analyst must:

1. review the evidence;
2. verify the timeline;
3. assess alternative explanations;
4. confirm the affected identity and asset;
5. review proposed actions;
6. provide explicit approval for high-impact actions.

The system must not bypass these controls.

## 11. Monitoring

A production implementation should monitor:

- false-positive and false-negative rates;
- analyst overrides;
- score calibration;
- feature drift;
- source availability;
- approval frequency;
- action failures;
- audit-chain integrity;
- prompt-injection detection.

## 12. Retirement / Change Control

Changes to:

- features;
- weights;
- thresholds;
- enrichment sources;
- response actions;

should be version-controlled and re-tested before use.

Any production deployment would require a new validation cycle and documented approval.

## 13. AI-Assistance Disclosure

AI assistance was used during development for explanation, drafting, troubleshooting, and documentation support.

All generated or assisted material must be reviewed and verified by the student before submission.

The student remains responsible for the final implementation, evidence interpretation, and submitted conclusions.

