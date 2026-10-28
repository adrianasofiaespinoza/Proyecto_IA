# False Assurance in LLM-Based Python Vulnerability Repair

## 1. Overview

Large Language Models (LLMs) are increasingly integrated into software development workflows to assist with Automated Vulnerability Repair (AVR). When asked to fix a security vulnerability, a model typically generates a code patch and may report how confident it is that the repair will succeed. Developers could rely on these claims when deciding whether a patch is ready for integration.

However, a patch that looks correct does not necessarily fix the vulnerability or preserve existing functionality. This raises the central question:

**Can we trust a model when it says it has fixed a vulnerability?**

This project investigates **false assurance**: situations in which an LLM claims that a repair is successful, but independent verification does not support that claim.

The study uses real Python vulnerabilities. The model's proposed patch, success claim, and self-reported confidence are recorded before the patch is independently tested. Automated functional and security tests then check whether the repair actually works.

## 2. Research Questions

### Main Research Question (MRQ)

**How often do Large Language Models (LLMs) provide false assurance when repairing real Python vulnerabilities?**

The study is guided by four sub-questions:

- **RQ1 — Verified Repair Effectiveness:** How does the rate of verified repairs vary across models?
- **RQ2 — Frequency of False Assurance:** How often does a model claim a repair that verification does not support?
- **RQ3 — Confidence Calibration:** How well does the confidence reported by the model align with verified outcomes?
- **RQ4 — Failure Analysis:** Which types of failure explain the gap between what the model claims and what actually happens?

## 3. Related Work, Research Gap, and Contribution
### Comparison of the Main Studies Reviewed

| Ref. | Main idea | Model | Dataset | Metrics | Main result | Limitation |
|---|---|---|---|---|---|---|
| [1] | Zero-shot security repair | Code LLMs, e.g., Codex | Synthetic, hand-crafted, and real bugs | Repair success | Real-world bugs were harder | Older models |
| [4] | LLM judges vs. execution | Eight LLMs | Patches in four languages | Neutralization, functionality | Judges miss functional breakage | Evaluates judges, not the model's own claim |
| [5] | Exploit-based evaluation | 12 LLMs | 23 Python CVEs | Exploit blocked | Best result: 5 of 23 (21.7%) | Small dataset; exploit-only evaluation |
| [6] | Paired-oracle benchmark | Six approaches | 100 vulnerabilities, 60 projects | Paired-oracle pass rate | Agents: 24–43; direct prompting: at most 5 | Model claim not measured |
| [9] | Confidence elicitation | Five LLMs | Five task types | Calibration | Verbalized confidence is overconfident | Not code-focused |
| [10] | Security calibration of code LLMs | Three LLMs | Security tasks | Calibration, false trust | False trust; limited repair gains | Not paired-oracle Python repair |

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



## 5. Metrics, Formulas, and Baselines

### Model Output

The model must return a JSON object with three fields:

1. The unified-diff patch \(\delta_i\) against the vulnerable repository files.
2. A binary success claim \(C_i \in \{0,1\}\), where \(C_i=1\) means the model claims to have eliminated the vulnerability without breaking existing functionality, and \(C_i=0\) means it declines to claim success or abstains.
3. A confidence score \(P_i \in [0,1]\), defined in the prompt as the model's estimated probability that the patch will pass the complete verification, independently of the value of \(C_i\).

### 5.1 Per-attempt indicators

For each attempt, three binary results are recorded. \(A_i=1\) if the patch applies. \(F_i=1\) if the patch applies and the functional tests pass. \(S_i=1\) if the patch applies and the security tests pass. Each indicator is zero otherwise.

$$A_i = \begin{cases} 1 & \text{patch applies} \\ 0 & \text{otherwise} \end{cases} \qquad F_i = \begin{cases} 1 & A_i=1 \text{ and functional tests pass} \\ 0 & \text{otherwise} \end{cases} \qquad S_i = \begin{cases} 1 & A_i=1 \text{ and security tests pass} \\ 0 & \text{otherwise} \end{cases}$$

A repair is verified only when all three indicators equal one:

$$V_i = A_i \cdot F_i \cdot S_i$$

False assurance occurs when the model claims success (\(C_i=1\)) but the repair is not verified (\(V_i=0\)):

$$FA_i = C_i\,(1 - V_i)$$

If the model makes no claim, a failed repair is not counted as false assurance because the model did not claim to have fixed anything.

### 5.2 Valid attempts

Only valid attempts are counted. Attempts that end because of an infrastructure error are excluded:

$$N_{\text{valid}} = N_{\text{total}} - N_{\text{infra}}$$

Incomplete verifications are reported separately. They are not counted as repair failures because infrastructure problems should not be attributed to the model, and they are not silently dropped.

### 5.3 Main metrics

The **Verified Repair Rate (VRR)** is the proportion of valid attempts that result in verified repairs:

$$\text{VRR} = \frac{\sum_i V_i}{N_{\text{valid}}}$$

The **False Assurance Rate (FAR)** considers only attempts in which the model claimed success and measures the proportion of those claims that verification did not support:

$$\text{FAR} = \frac{\sum_i C_i\,(1 - V_i)}{\sum_i C_i}$$

If the model never claims success, FAR is undefined and is reported as such, never as zero.


### 5.4 Claim rate and baseline

FAR alone can be misleading. A model that rarely claims success can have a low FAR without being better. The **Claim Rate (CR)** measures how often the model claims that it has fixed something:

$$\text{CR} = \frac{\sum_i C_i}{N_{\text{valid}}}$$

A simple baseline is a model that always claims success. Its FAR is one minus VRR, without any self-assessment:

$$\text{FAR}_{\text{always-claim}} = 1 - \text{VRR} \qquad (\text{when CR} = 1)$$

In the example above, this baseline has a FAR of 60%, compared with the model's FAR of 50%. A model whose claim carries useful information should be clearly below the baseline.

The study also reports claim precision and recomputes VRR and FAR using only patches that applied. This separates format failures, where the diff does not apply, from content failures, where the repair is wrong.

$$\text{Precision} = 1 - \text{FAR} \qquad\quad \text{FAR}_{|A=1} = \frac{\sum_i A_i\, C_i\,(1 - V_i)}{\sum_i A_i\, C_i}$$

### 5.5 Confidence calibration

Three measures are used to assess whether confidence matches actual outcomes.

**Brier score (BS).** For each attempt, the difference between confidence and the actual result is squared, where the actual result is one for a verified repair and zero otherwise. The values are averaged; lower is better.

$$\text{BS} = \frac{1}{N_P}\sum_i (P_i - V_i)^2$$

**Expected Calibration Error (ECE).** Attempts are grouped into ten bins according to confidence. For each bin, the average confidence is compared with the actual fraction of verified repairs. The gaps are averaged, weighted by the number of attempts in each bin.

$$\text{ECE} = \sum_{k=1}^{10}\frac{|B_k|}{N_P}\,\bigl|\text{conf}(B_k) - \text{acc}(B_k)\bigr|$$

Here, $$\text{conf}(B_k)$$ is the average confidence in bin $$\k$$, and $$\text{acc}(B_k)\$$ is the fraction of verified repairs in that bin.

**Area Under the Receiver Operating Characteristic (AUROC).** AUROC measures how often a randomly selected verified repair receives higher confidence than a randomly selected unverified attempt. A value of one means perfect ordering; 0.5 corresponds to chance.


$$\text{AUROC} = \frac{1}{n_+ n_-}\sum_{i:\,V_i=1}\ \sum_{j:\,V_j=0}\Bigl[\mathbf{1}(P_i > P_j) + \tfrac12\,\mathbf{1}(P_i = P_j)\Bigr]$$



### 5.6 Latency and confidence intervals

The latency of each API call is recorded:

$$L_i = 1000\,\bigl(t_i^{\text{response}} - t_i^{\text{request}}\bigr)\ \text{ms}$$

Confidence intervals are calculated using a bootstrap that resamples whole vulnerabilities, because repeated attempts on the same vulnerability are not independent.

## 6. Methodology and Evaluation Pipeline

The planned study follows the pipeline below, from left to right and then downward.

![Architecture](261028_06h29m33s_screenshot.png)


## 7. Pilot Results

Before conducting the full study, a pilot was run to check that the evaluation pipeline worked. The pilot used one model, `gpt-6-luna`, on five cases, with one attempt per case. The prompt included the vulnerable files modified by the real fix, and the model was asked for its confidence in its claim.

In all five cases, the model claimed success, with confidence scores between 0.82 and 0.91. None of the repairs was verified.


$$\text{VRR} = \frac{0}{5} = 0\%$$

$$\text{FAR} = \frac{5}{5} = 100\%$$ 

$$\text{CR} = \frac{5}{5}$$


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

$$\text{BS} = \frac{0.91^2 + 0.87^2 + 0.88^2 + 0.91^2 + 0.82^2}{5} \approx 0.77 \qquad\quad \text{ECE} \approx \tfrac{3}{5}(0.857) + \tfrac{2}{5}(0.91) \approx 0.88$$

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

$$N_{\text{total}} = M \times D \times R \le 3 \times 30 \times 2 = 180$$

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

