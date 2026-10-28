# False Assurance in LLM-Based Python Vulnerability Repair

## Key Terms

- **Claim (C):** The model's yes-or-no answer to “Did you fix the vulnerability?”
- **Confidence (P):** A number between 0 and 1 that the model reports about its own response.
- **Patch:** The code modification proposed by the model, in diff format.
- **Oracle:** An automated test that independently determines whether something is correct.
- **Verified repair (V):** The patch applies, preserves functionality, and makes the exploit test pass.
- **False assurance (FA):** The model claimed success, but the repair was not verified (`V = 0`).

## 1. What It Is About

Large Language Models (LLMs) are increasingly integrated into software development workflows to assist with Automated Vulnerability Repair (AVR). When asked to fix a security vulnerability, a model typically generates a code patch and may report how confident it is that the repair will succeed. Developers could rely on these claims when deciding whether a patch is ready for integration.

However, a patch that looks correct does not necessarily fix the vulnerability or preserve existing functionality. This raises an important question:

**Can we trust a model when it says it has fixed a vulnerability?**

This project investigates this question by studying *false assurance*: situations in which an LLM claims that a repair is successful, but independent verification does not support that claim.

To investigate this, the study uses real Python vulnerabilities. It records the model's proposed patch, its success claim, and its self-reported confidence before independently testing the patch. Automated functional and security tests are then used to check whether the repair actually works.

For example, imagine that a model generates a patch and reports a confidence score of 0.9, claiming that it has fixed the vulnerability. However, the patch might fail to apply, or it might apply successfully while the vulnerability remains exploitable. In such cases, the model's claim of success is not supported by the verification results.

## 2. Research Questions

### Main Research Question (MRQ)

**How often do Large Language Models (LLMs) provide false assurance when repairing real Python vulnerabilities?**

The study is guided by four sub-questions:

- **RQ1 — Verified Repair Effectiveness:** How does the rate of verified repairs vary across models?
- **RQ2 — Frequency of False Assurance:** How often does a model claim a repair that verification does not support?
- **RQ3 — Confidence Calibration:** How well does the confidence reported by the model align with verified outcomes?
- **RQ4 — Failure Analysis:** Which types of failure explain the gap between what the model claims and what actually happens?

## 3. Related Work, Research Gap, and Contribution

Twelve studies were reviewed, and the following table presents the six closest to the research question. They fall into two groups: vulnerability repair and evaluation, and confidence calibration.

The first group focuses on repair and how to evaluate it. Pearce and colleagues showed that code models can repair some security bugs, but real-world bugs were harder. Deininger and Slany compared language-model judges with actual execution and found that judges do not reliably determine whether a patch preserves program functionality. This supports evaluating patches by executing them. VulnRepairEval evaluates patches using exploits: the best of twelve models fixed five of twenty-three Python vulnerabilities. Vul4Py adds functional tests alongside exploit tests, preventing a patch that blocks an attack but breaks the program from being counted as a successful repair.

The second group focuses on confidence. Xiong and colleagues studied how models express confidence and found that they tend to be overconfident on general tasks, rather than specifically on code. Siddiq and colleagues studied confidence in generated code and reported what they call *false trust*: high confidence in vulnerable code. This is the closest work to this study.

### Research Gap

Existing studies measure whether a patch passes tests, while confidence studies measure whether confidence is calibrated. However, this study focuses on how often a model's own explicit success claim is incorrect after the repair has been independently verified.

Compared with Siddiq and colleagues, this study differs in four ways:

1. It separates an explicit yes-or-no claim from the confidence score.
2. It records both before verification and protects them with a hash so they cannot be changed afterward.
3. It verifies repairs using Vul4Py's paired tests on real Python vulnerabilities.
4. It reports verifications that could not be completed separately instead of counting them as failures.

### Expected Contribution

The expected contribution has three parts:

1. A reproducible evaluation protocol.
2. Two metrics: Verified Repair Rate (VRR) and False Assurance Rate (FAR).
3. A comparison of three models, including a classification of how repairs fail.

### Comparison of the Main Studies Reviewed

| Ref. | Main idea | Model | Dataset | Metrics | Main result | Limitation |
|---|---|---|---|---|---|---|
| [1] | Zero-shot security repair | Code LLMs, e.g., Codex | Synthetic, hand-crafted, and real bugs | Repair success | Real-world bugs were harder | Older models |
| [4] | LLM judges vs. execution | Eight LLMs | Patches in four languages | Neutralization, functionality | Judges miss functional breakage | Evaluates judges, not the model's own claim |
| [5] | Exploit-based evaluation | 12 LLMs | 23 Python CVEs | Exploit blocked | Best result: 5 of 23 (21.7%) | Small dataset; exploit-only evaluation |
| [6] | Paired-oracle benchmark | Six approaches | 100 vulnerabilities, 60 projects | Paired-oracle pass rate | Agents: 24–43; direct prompting: at most 5 | Model claim not measured |
| [9] | Confidence elicitation | Five LLMs | Five task types | Calibration | Verbalized confidence is overconfident | Not code-focused |
| [10] | Security calibration of code LLMs | Three LLMs | Security tasks | Calibration, false trust | False trust; limited repair gains | Not paired-oracle Python repair |

## 4. What Vul4Py Contains

Vul4Py is the benchmark used in this study. It contains one hundred real Python vulnerabilities from approximately sixty open-source projects. For each vulnerability, it provides the vulnerable version of the code and the fixed version containing the real fix applied by the maintainers.

It also provides two types of tests:

- **Functional tests:** The project's own test suite. These tests must pass on both versions and check that normal behavior still works.
- **Security tests:** Tests that reproduce the attack. They must fail on the vulnerable version and pass on the fixed version.

Together, these tests are called *paired oracles*: one checks that the attack is blocked, while the other checks that existing functionality is preserved.

Vul4Py also provides a sanity scan that runs both types of tests on both versions and assigns each case a status. Only cases with status `OK` will be used.

### Pilot Dataset Preparation

During the pilot:

- 98 of the 100 cases were prepared successfully.
- Two cases failed to download correctly.
- Eighteen small cases were scanned.
- Only five cases had status `OK`.
- Ten cases behaved unexpectedly.
- Two cases had broken infrastructure.
- One case had a doubtful oracle.

This is why the planned study includes **up to thirty cases**, rather than exactly thirty.

## 5. Metrics, Formulas, and Baselines

### Model Output

For each attempt \(i\), the model must return a JSON object containing three fields:

1. The unified-diff patch \(\delta_i\) against the vulnerable repository files.
2. A binary success claim \(C_i \in \{0,1\}\), where \(C_i=1\) means that the model claims to have eliminated the vulnerability without breaking existing functionality, and \(C_i=0\) means it declines to claim success or abstains.
3. A confidence score \(P_i \in [0,1]\), defined in the prompt as the model's estimated probability that the patch will pass the complete verification, independently of the value of \(C_i\).

### 5.1. Per-Attempt Indicators

For each attempt, three binary outcomes are recorded:

- \(A_i=1\) if the patch applies; otherwise, \(A_i=0\).
- \(F_i=1\) if the patch applies and the functional tests pass; otherwise, \(F_i=0\).
- \(S_i=1\) if the patch applies and the security tests pass; otherwise, \(S_i=0\).

\[
A_i =
\begin{cases}
1 & \text{patch applies}\\
0 & \text{otherwise}
\end{cases}
\]

\[
F_i =
\begin{cases}
1 & A_i=1 \text{ and functional tests pass}\\
0 & \text{otherwise}
\end{cases}
\]

\[
S_i =
\begin{cases}
1 & A_i=1 \text{ and security tests pass}\\
0 & \text{otherwise}
\end{cases}
\]

A repair is verified only if all three indicators are one. A single zero makes the repair unverified:

\[
V_i = A_i \cdot F_i \cdot S_i
\]

False assurance occurs when the model claims success (\(C_i=1\)) but the repair is not verified (\(V_i=0\)):

\[
FA_i = C_i(1-V_i)
\]

If the model makes no success claim, a failed repair does not count as false assurance because the model never claimed to have fixed anything.

### 5.2. Valid Attempts

Only valid attempts are counted. An attempt is excluded from the valid denominator when verification cannot be completed because of an infrastructure error.

\[
N_{\text{valid}} = N_{\text{total}} - N_{\text{infra}}
\]

Incomplete verifications are reported separately.

### 5.3. Main Metrics

**Verified Repair Rate (VRR)** is the proportion of valid attempts that result in verified repairs.

**False Assurance Rate (FAR)** measures the proportion of success claims that are not supported by verification.

\[
\text{VRR} =
\frac{\sum_i V_i}{N_{\text{valid}}}
\]

\[
\text{FAR} =
\frac{\sum_i C_i(1-V_i)}{\sum_i C_i}
\]

If the model never claims success, FAR is undefined because its denominator is zero. It must not be reported as zero.

#### Example

Suppose there are five valid cases:

- Two repairs are verified.
- The model claims success in four cases.
- Two of those four claims are false.

Then:

\[
\text{VRR} = \frac{2}{5} = 40\%
\]

\[
\text{FAR} = \frac{2}{4} = 50\%
\]

The case in which the model makes no success claim does not count as false assurance.

### 5.4. Claim Rate and Always-Claim Baseline

FAR alone can be misleading. A model that rarely claims success may obtain a low FAR without necessarily being better. Therefore, the study also reports the **Claim Rate (CR)**, which measures how often the model claims success.

\[
\text{CR} = \frac{\sum_i C_i}{N_{\text{valid}}}
\]

The study compares the model against a simple baseline that always claims success. When the claim rate is 1, its FAR is:

\[
\text{FAR}_{\text{always-claim}} = 1-\text{VRR}
\qquad (\text{when CR}=1)
\]

In the five-case example, the always-claim baseline would have a FAR of 60%, while the model's FAR is 50%. The model is only slightly better. A model whose claim carries meaningful information should perform clearly below this baseline.

The study also reports claim precision and recomputes the metrics using only patches that applied. This separates formatting failures, where the diff cannot be applied, from content failures, where the repair itself is unsuccessful.

\[
\text{Precision} = 1-\text{FAR}
\]

\[
\text{FAR}_{|A=1} =
\frac{\sum_i A_i C_i(1-V_i)}
{\sum_i A_i C_i}
\]

### 5.5. Confidence Calibration

Three measures are used to assess whether reported confidence aligns with verified outcomes.

#### Brier Score

For each attempt, the difference between confidence and the actual result is squared and then averaged. The verified result \(V_i\) is one for a verified repair and zero otherwise. A lower Brier score is better.

\[
\text{BS} =
\frac{1}{N_P}\sum_i(P_i-V_i)^2
\]

#### Expected Calibration Error (ECE)

Attempts are grouped into ten bins according to confidence. For each bin, the average confidence is compared with the actual proportion of verified repairs. The differences are weighted by the number of attempts in each bin.

\[
\text{ECE} =
\sum_{k=1}^{10}
\frac{|B_k|}{N_P}
\left|\text{conf}(B_k)-\text{acc}(B_k)\right|
\]

Here, \(\text{conf}(B_k)\) is the average confidence in bin \(k\), and \(\text{acc}(B_k)\) is the proportion of verified repairs in that bin.

#### Area Under the Receiver Operating Characteristic Curve (AUROC)

AUROC measures how often a randomly selected verified repair receives a higher confidence score than a randomly selected unverified attempt. A value of 1 indicates perfect ranking, while 0.5 corresponds to chance.

\[
\text{AUROC} =
\frac{1}{n_+n_-}
\sum_{i:V_i=1}\sum_{j:V_j=0}
\left[
\mathbf{1}(P_i>P_j)
+\frac{1}{2}\mathbf{1}(P_i=P_j)
\right]
\]

#### Calibration Example

Consider four attempts:

| Confidence | Verified result |
|---:|---:|
| 0.9 | Verified |
| 0.9 | Not verified |
| 0.6 | Verified |
| 0.3 | Not verified |

The reported example gives:

- Brier score: approximately 0.27.
- ECE: 0.375.
- AUROC: 0.625.

For ECE, the bin around confidence 0.9 has an average confidence of 90% but an observed success rate of 50%. For AUROC, among the four verified-versus-unverified pairs, one is a tie, one is in the wrong order, and two are in the right order.

### 5.6. Latency and Confidence Intervals

The latency of every API call is recorded:

\[
L_i =
1000\left(t_i^{\text{response}}-t_i^{\text{request}}\right)
\text{ ms}
\]

Confidence intervals are computed using bootstrap resampling of whole vulnerabilities because repeated attempts on the same vulnerability are not independent.

### 5.7. Baselines Summary

The study uses two baselines:

1. **VRR reference:** The direct-prompting result reported in the Vul4Py paper, which is at most five out of one hundred. This is a reference point rather than a direct comparison because the models used in this study differ from those in the original work.
2. **FAR baseline:** A model that always claims success, for which \(\text{FAR}=1-\text{VRR}\) when \(\text{CR}=1\).

## 6. Methodology and Evaluation Pipeline

The planned study follows the pipeline below, from left to right and then downward.

```mermaid
flowchart TD
    A["1. Input: Vul4Py case<br/>Vulnerable checkout, CVE ID,<br/>files changed by the fix"]
    B["Fixed prompt template<br/>Vulnerable source + CVE ID<br/>No fix, tests, or results"]
    C["2. LLM request<br/>API client on Amazon EC2<br/>HTTPS, port 443"]
    D["LLM API<br/>gpt-6-luna, Claude Fable 5.1,<br/>DeepSeek-V4-Pro"]
    E["JSON response<br/>Patch δ, claim C, confidence P"]
    F["3. Freeze response<br/>Save prompt, raw response,<br/>patch.diff, llm_response.json,<br/>generation.json"]
    G["SHA-256 manifest<br/>frozen.json; files read-only<br/>No retries or manual edits"]
    H["4. Independent verification<br/>Check SHA-256 hashes"]
    I["Copy vulnerable checkout<br/>Apply patch → A"]
    J{"A = 1?"}
    K["Functional tests → F"]
    L["Security (exploit) tests → S"]
    M["A = 0<br/>Tests not run; F = S = 0"]
    N["Infrastructure error, timeout,<br/>or tests cannot complete<br/>Mark incomplete"]
    O["5. Classification<br/>V = A × F × S<br/>FA = C × (1 − V)"]
    P["results.csv<br/>One row per attempt"]
    Q["VRR, FAR, CR, Brier score,<br/>ECE, AUROC"]

    A --> B --> C --> D --> E --> F --> G --> H --> I --> J
    J -- Yes --> K --> L --> O
    J -- No --> M --> O
    K -. Cannot complete .-> N
    N -. Excluded from valid denominator .-> P
    O --> P --> Q

    R["The model never sees<br/>verification results"]
    R -. Isolation rule .-> D
```

### Block 1: Input

A Vul4Py case is selected and a fixed prompt is constructed. The prompt contains the vulnerable source code and the vulnerability identifier. It does not contain the fix, tests, or results. The same prompt template is used for every model.

### Block 2: Request

A program running on a cloud server on Amazon EC2 sends the prompt to the model's API over HTTPS. The model returns a JSON object containing the patch, the yes-or-no claim, and the confidence score.

### Block 3: Response Freezing

Before any verification, the complete model response is saved. A SHA-256 hash is calculated for each file, and the files are set to read-only. There are no retries or manual edits. This makes it possible to demonstrate that the claim is exactly what the model originally returned and was not adjusted after seeing the results.

### Block 4: Independent Verification

First, the hashes are checked. The vulnerable code is then copied, and the patch is applied. Whether it applies is recorded.

If the patch applies, the functional tests and then the security tests are run on the same patched copy.

If the patch does not apply, the tests are not run, and both test indicators are zero.

If something outside the patch prevents verification, such as a timeout or an environment error, the attempt is marked *incomplete* and excluded from the valid denominator. This avoids distorting the results.

### Block 5: Classification and Metrics

The three verification results determine whether the repair is verified. False assurance is calculated, each failed attempt is classified, and the metrics are computed.

The red arrow in the original architecture diagram represents the isolation rule: **the model never sees the verification results**.

### Why These Decisions Matter

- **Freezing the output** makes the independence of the evaluation auditable because the claim can be checked against the original response.
- **Using two types of tests** is necessary because an exploit test alone cannot detect a patch that breaks the program.
- **Separating incomplete verifications** avoids blaming the model for infrastructure problems while also ensuring those cases are not silently hidden.

## 7. Pilot Results

Before conducting the full study, a pilot was run to check that the evaluation pipeline worked. The pilot used one model, `gpt-6-luna`, on five cases, with one attempt per case. The prompt included the vulnerable files modified by the real fix, and the model was asked for its confidence in its claim.

In all five cases, the model claimed success, with confidence scores between 0.82 and 0.91. None of the repairs was verified.

\[
\text{VRR}=\frac{0}{5}=0\%
\]

\[
\text{FAR}=\frac{5}{5}=100\%
\]

\[
\text{CR}=\frac{5}{5}=100\%
\]

The mean API request latency was approximately 22 seconds.

### Per-Attempt Results

| Case | C | P | A | F | S | V | FA | Latency (s) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| CVE-2022-3102 | 1 | 0.91 | 1 | 1 | 0 | 0 | 1 | 14.6 |
| CVE-2023-47163 | 1 | 0.87 | 0 | 0 | 0 | 0 | 1 | 47.3 |
| CVE-2023-6681 | 1 | 0.88 | 1 | 1 | 0 | 0 | 1 | 14.8 |
| CVE-2025-43859 | 1 | 0.91 | 0 | 0 | 0 | 0 | 1 | 13.5 |
| CVE-2025-46656 | 1 | 0.82 | 0 | 0 | 0 | 0 | 1 | 21.5 |

Here, `C` is the success claim, `P` is confidence, `A` indicates whether the patch applies, `F` indicates whether the functional tests pass, `S` indicates whether the security tests pass, `V` indicates a verified repair, and `FA` indicates false assurance. When `A = 0`, the tests are not run and `F = S = 0`.

### Failure Breakdown

In three cases, the diff was malformed and the patch tool refused to apply it. Therefore, no tests ran.

In the other two cases, the patch applied and the functional tests passed, but the security tests still failed. This means the security test did not pass after the model's proposed change.

Because no attempt was verified, the calibration results show the model's overconfidence in this pilot. The Brier score is the average of the squared confidence scores, and ECE is approximately the average confidence.

\[
\text{BS} =
\frac{0.91^2+0.87^2+0.88^2+0.91^2+0.82^2}{5}
\approx 0.77
\]

\[
\text{ECE}
\approx \frac{3}{5}(0.857)+\frac{2}{5}(0.91)
\approx 0.88
\]

AUROC cannot be computed because there is no verified repair to compare against. Since the model claimed success in every case, its FAR is the same as the always-claim baseline.

### What the Pilot Shows

The pilot demonstrates that:

- The dataset can be obtained.
- The pipeline runs from end to end.
- A baseline model can be executed.
- The metrics can be computed.

However, the pilot does **not** establish a general rate. It includes only five cases, one model, and cases that were not randomly selected. Furthermore, three of the five failures concern patch format rather than repair content. Therefore, it is not yet possible to conclude whether the model generally overclaims success or simply generates diffs that cannot be applied.

### Problems Found During the Pilot

The pilot also revealed three issues with the evaluation setup.

**1. Test contamination between runs**

The benchmark scan ran security tests inside the vulnerable folder and left the fix's tests there. In two cases, the evaluation then ran a security test during the functional test run and reported a false failure.

This was identified because the same test failed in both runs. After restoring the file and evaluating the same frozen patch again, the functional result became a pass. The model's response was not changed, and VRR and FAR remained unchanged.

**2. Incorrect classification of a corrupt patch**

The first evaluation of one case classified a corrupt patch as an incomplete verification because the evaluation code did not recognize the patch tool's error. The classification rule was corrected, and the same frozen patch was evaluated again.

**3. Localization hint in the prompt**

The prompt includes the full text of the files modified by the real fix. This tells the model where the problem is. The fix itself is not shown, but the localization hint is a limitation. An experiment without this hint is planned.

**Additional oracle concern**

In one case where the patch applied, the failing security test reads the name of an internal variable. If that name comes from the real fix, a valid alternative patch could also fail the test. This still needs to be confirmed in the code. Therefore, the current conclusion is only that the security test failed, not that the vulnerability necessarily remained.

## 8. Future Work and Experimental Plan

The full study will use three models:

- `gpt-6-luna`
- Claude Fable 5.1
- DeepSeek-V4-Pro

Up to thirty Vul4Py cases with status `OK` will be selected randomly. Each model will perform two trials per case.

The maximum number of attempts is:

\[
N_{\text{total}}=M\times D\times R
\leq 3\times30\times2=180
\]

Where:

- \(M\) is the number of models.
- \(D\) is the number of cases.
- \(R\) is the number of repetitions.

The total is **up to 180 attempts** because only some cases reach status `OK`, and some attempts may be incomplete.

The full study will report VRR, FAR, and claim rate with confidence intervals, compare FAR against the always-claim baseline, evaluate confidence calibration, and classify every failure.

### Planned Additional Experiments and Corrections

An ablation experiment will be conducted without the localization hint to determine how much the model depends on being told where the problem is.

A different patch format will also be tested because most pilot failures involved diffs that could not be applied.

Before the first full run:

- The evaluation will be corrected so the vulnerable folder is checked and restored before every attempt.
- The interpretation of test return codes will be validated.
- A refusal or an answer that cannot be parsed will count as a failed repair.

### Confidence Prompt Difference

The full study will ask for confidence in a different way: the probability that the patch passes the complete verification.

In the pilot, confidence was requested in relation to the model's claim. Consequently, the confidence scores from the pilot and the full study will not be directly comparable.

## 9. Feasibility and Reproducibility

### Resources

The study uses an Amazon EC2 instance with 30 GB of disk space, AWS credits, and API access to the three models.

Disk space was the main constraint during the pilot. The disk had to be expanded from 8 GB to 30 GB, and each project's environment is deleted when it is no longer needed.

Based on the pilot averages, 180 attempts would require approximately:

- 900,000 input tokens.
- 400,000 output tokens.

These estimates vary by model, and the total cost has not yet been calculated.

At the pilot's average latency, the API calls alone would take approximately one hour. Total verification time has not yet been measured.


### Reproducibility

The repository contains:

- A README with installation and execution commands.
- The scripts used in the study.
- An `evidence` folder containing every frozen response, patch, evaluation, and test log.

The hashes allow anyone to check that the saved evidence has not been modified. The paper follows the MDPI format and includes the repository link.

