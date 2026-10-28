# False Assurance in LLM-Based Python Vulnerability Repair

## Research Overview

Large Language Models (LLMs) are increasingly used to repair software vulnerabilities. However, a model-generated patch may appear correct or be accompanied by a confident claim of success without actually fixing the underlying security issue.

This project investigates **false assurance in LLM-based Python vulnerability repair** by evaluating whether a model's claims of successful repair are supported by independent verification.

The study uses real Python vulnerabilities from Vul4Py and evaluates generated patches through a standardized workflow involving patch application, functional testing, and security verification.

## Main Research Question

**MRQ:** How often do Large Language Models (LLMs) provide false assurance when repairing real Python vulnerabilities?

The study is guided by four research questions:

- **RQ1 — Verified Repair Effectiveness:** How does the Verified Repair Rate (VRR) vary across LLMs under a standardized direct-prompting setup?
- **RQ2 — Frequency of False Assurance:** How often do LLMs claim a successful repair when independent verification does not confirm it?
- **RQ3 — Confidence and Verification:** To what extent does model-reported confidence predict independently verified repair success?
- **RQ4 — Failure Characterization:** What types of failures account for unsuccessful or unverified repairs?

## Research Motivation

LLMs can generate plausible code changes and report that a vulnerability has been fixed. However, the apparent quality of a patch does not guarantee that it applies correctly, preserves functionality, or prevents exploitation.

Evaluating only the generated patch or the model's own explanation can therefore overestimate repair effectiveness.

This study separates the model's claim from the actual outcome of independent verification. The goal is to measure the difference between perceived repair success and verified security improvement.

## Related Work

The study builds on research in automated program repair, LLM-based code generation, and software security evaluation.

| Research area | Main focus | Relevance to this study |
|---|---|---|
| Automated Program Repair | Automatically generating code changes to fix software defects | Provides the foundation for evaluating generated patches |
| LLM-Based Code Repair | Using language models to generate code fixes | Motivates the evaluation of LLM-generated vulnerability repairs |
| Vulnerability Detection and Security Testing | Identifying vulnerabilities and testing whether software remains exploitable | Supports independent security verification |
| Confidence and Calibration | Examining the relationship between model confidence and prediction correctness | Motivates the analysis of confidence and verified outcomes |
| This Study | Measuring false assurance in LLM-based Python vulnerability repair | Combines repair outcomes, functional testing, security verification, and model claims |

## Methodology

The evaluation follows a standardized pipeline designed to separate the LLM's reported success from the independently verified outcome.

```mermaid
flowchart TD
    A[Select real Python vulnerabilities from Vul4Py]
    B[Provide a standardized prompt to the LLM]
    C[Record the model's claim and confidence]
    D[Freeze the claim, confidence, and generated patch]
    E[Attempt to apply the patch]
    F[Run functional verification]
    G[Run security verification]
    H[Calculate repair metrics]
    I[Analyze false assurance and failure categories]

    A --> B
    B --> C
    C --> D
    D --> E
    E --> F
    F --> G
    G --> H
    H --> I
