# False Assurance in LLM-Based Python Vulnerability Repair

## Key terms

- **Claim (\(C\)):** the model's yes-or-no answer to “Did you fix the vulnerability?”
- **Confidence (\(P\)):** a number between 0 and 1 that the model reports for its own answer.
- **Patch:** the code modification proposed by the model, in diff format.
- **Oracle:** an automated test that independently determines whether something is correct.
- **Verified repair (\(V\)):** the patch applies, does not break existing functionality, and the exploit no longer works.
- **False assurance (FA):** the model claims success, but \(V=0\).

## 1. Overview

Large Language Models (LLMs) are increasingly integrated into software development workflows to assist with Automated Vulnerability Repair (AVR). When asked to fix a security vulnerability, a model typically generates a code patch and may report how confident it is that the repair will succeed. Developers could rely on these claims when deciding whether a patch is ready for integration.

However, a patch that looks correct does not necessarily fix the vulnerability or preserve existing functionality. This raises the central question:

**Can we trust a model when it says it has fixed a vulnerability?**

This project investigates **false assurance**: situations in which an LLM claims that a repair is successful, but independent verification does not support that claim.

The study uses real Python vulnerabilities. The model's proposed patch, success claim, and self-reported confidence are recorded before the patch is independently tested. Automated functional and security tests then check whether the repair actually works.

For example, a model may generate a patch and report confidence of 0.9 while claiming that it fixed the vulnerability. The patch may fail to apply, or it may apply successfully while the vulnerability remains exploitable. In these cases, verification does not support the model's claim.

## 2. Research questions

### Main research question (MRQ)

**How often do Large Language Models (LLMs) provide false assurance when repairing real Python vulnerabilities?**

### Sub-questions

- **RQ1 — Verified Repair Effectiveness:** How does the Verified Repair Rate (VRR) vary across models?
- **RQ2 — Frequency of False Assurance:** How often does a model claim a repair that verification does not support?
- **RQ3 — Confidence Calibration:** How well does the confidence reported by the model align with verified outcomes?
- **RQ4 — Failure Analysis:** Which types of failure explain the gap between what the model claims and what actually happens?

## 3. Related work, research gap, and contribution

Twelve studies were reviewed, including six that are closest to this research question. They fall into two groups: vulnerability repair and evaluation, and confidence in model-generated outputs.

### Vulnerability repair and evaluation

Pearce and colleagues showed that code models can repair some security bugs, although real-world bugs were more difficult. Deininger and Slany compared language-model judges with real execution and found that judges do not reliably determine whether a patch preserves program functionality. This supports evaluating patches by running them.

VulnRepairEval evaluates repairs with exploits; the best of twelve models fixed five of twenty-three Python vulnerabilities. Vul4Py adds functional tests alongside exploit tests, so a patch that blocks an attack but breaks the program is not counted as a successful repair.

### Confidence

Xiong and colleagues studied how models express confidence and found that they tend to be overconfident on general tasks, rather than specifically on code. Siddiq and colleagues studied confidence in generated code and reported **false trust**: high confidence in vulnerable code. This is the closest work to this study.

### Research gap

Existing studies measure whether a patch passes tests, while confidence studies measure whether confidence is calibrated. The gap addressed here is measuring how often a model's own claim is wrong after the repair has been independently verified.

### Expected contribution

This study differs from the closest work in four ways:

1. It separates an explicit yes-or-no claim from the confidence score.
2. It records both before verification and protects them with a hash so they cannot be changed afterwards.
3. It verifies repairs with Vul4Py's paired tests on real Python vulnerabilities.
4. It reports verifications that could not finish separately instead of counting them as failures.

The expected contribution consists of a reproducible protocol, the VRR and FAR metrics, and a comparison of three models with a classification of repair failures.

## 4. Vul4Py benchmark

Vul4Py is the benchmark used in this study. It contains one hundred real Python vulnerabilities from approximately sixty open-source projects. For each vulnerability, it provides the vulnerable version of the code and the fixed version containing the real fix applied by the maintainers.

It includes two kinds of tests:

- **Functional tests:** the project's own test suite, which must pass on both versions and checks that normal behavior still works.
- **Security tests:** tests that reproduce the attack. They must fail on the vulnerable version and pass on the fixed version.

Together, these are called **paired oracles**: one checks that the attack is blocked, while the other checks that existing functionality is preserved.

Vul4Py also provides a sanity scan that runs both kinds of tests on both versions and assigns each case a status. Only cases with status `OK`, meaning that the tests behave as expected, are used.

In the pilot, 98 of the 100 cases were prepared; two failed to download correctly. Eighteen small cases were scanned, and only five were `OK`: ten behaved unexpectedly, two had broken infrastructure, and one had a doubtful oracle. Therefore, the planned study uses **up to thirty cases**, rather than exactly thirty.

## 5. Model output and evaluation metrics

The model must return a JSON object with three fields:

1. The unified-diff patch \(\delta_i\) against the vulnerable repository files.
2. A binary success claim \(C_i \in \{0,1\}\), where \(C_i=1\) means the model claims to have eliminated the vulnerability without breaking existing functionality, and \(C_i=0\) means it declines to claim success or abstains.
3. A confidence score \(P_i \in [0,1]\), defined in the prompt as the model's estimated probability that the patch will pass the complete verification, independently of the value of \(C_i\).

### 5.1 Per-attempt indicators

For each attempt, three binary results are recorded. \(A_i=1\) if the patch applies. \(F_i=1\) if the patch applies and the functional tests pass. \(S_i=1\) if the patch applies and the security tests pass. Each indicator is zero otherwise.

\[
A_i =
\begin{cases}
1 & \text{patch applies}\\
0 & \text{otherwise}
\end{cases}
\qquad
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

A repair is verified only when all three indicators equal one:

\[
V_i = A_i \cdot F_i \cdot S_i
\]

False assurance occurs when the model claims success (\(C_i=1\)) but the repair is not verified (\(V_i=0\)):

\[
FA_i = C_i(1 - V_i)
\]

If the model makes no claim, a failed repair is not counted as false assurance because the model did not claim to have fixed anything.

### 5.2 Valid attempts

Only valid attempts are counted. Attempts that end because of an infrastructure error are excluded:

\[
N_{\text{valid}} = N_{\text{total}} - N_{\text{infra}}
\]

Incomplete verifications are reported separately. They are not counted as repair failures because infrastructure problems should not be attributed to the model, and they are not silently dropped.

### 5.3 Main metrics

The **Verified Repair Rate (VRR)** is the proportion of valid attempts that result in verified repairs:

\[
\text{VRR} = \frac{\sum_i V_i}{N_{\text{valid}}}
\]

The **False Assurance Rate (FAR)** considers only attempts in which the model claimed success and measures the proportion of those claims that verification did not support:

\[
\text{FAR} = \frac{\sum_i C_i(1 - V_i)}{\sum_i C_i}
\]

If the model never claims success, FAR is undefined and is reported as such, never as zero.

For example, if two of five cases are verified, VRR is 40%. If the model claims success in four cases and two of those claims are false, FAR is 50%. The case in which the model makes no claim is not counted as false assurance.

\[
\text{VRR} = \frac{2}{5} = 40\%
\qquad
\text{FAR} = \frac{2}{4} = 50\%
\]

### 5.4 Claim rate and baseline

FAR alone can be misleading. A model that rarely claims success can have a low FAR without being better. The **Claim Rate (CR)** measures how often the model claims that it has fixed something:

\[
\text{CR} = \frac{\sum_i C_i}{N_{\text{valid}}}
\]

A simple baseline is a model that always claims success. Its FAR is one minus VRR, without any self-assessment:

\[
\text{FAR}_{\text{always-claim}} = 1 - \text{VRR}
\qquad (\text{when CR}=1)
\]

In the example above, this baseline has a FAR of 60%, compared with the model's FAR of 50%. A model whose claim carries useful information should be clearly below the baseline.

The study also reports claim precision and recomputes VRR and FAR using only patches that applied. This separates format failures, where the diff does not apply, from content failures, where the repair is wrong.

\[
\text{Precision} = 1 - \text{FAR}
\]

\[
\text{FAR}_{|A=1} =
\frac{\sum_i A_i C_i(1 - V_i)}{\sum_i A_i C_i}
\]

### 5.5 Confidence calibration

Three measures are used to assess whether confidence matches actual outcomes.

**Brier score (BS).** For each attempt, the difference between confidence and the actual result is squared, where the actual result is one for a verified repair and zero otherwise. The values are averaged; lower is better.

\[
\text{BS} = \frac{1}{N_P}\sum_i (P_i - V_i)^2
\]

**Expected Calibration Error (ECE).** Attempts are grouped into ten bins according to confidence. For each bin, the average confidence is compared with the actual fraction of verified repairs. The gaps are averaged, weighted by the number of attempts in each bin.

\[
\text{ECE} =
\sum_{k=1}^{10}
\frac{|B_k|}{N_P}
\left|\text{conf}(B_k)-\text{acc}(B_k)\right|
\]

Here, \(\text{conf}(B_k)\) is the average confidence in bin \(k\), and \(\text{acc}(B_k)\) is the fraction of verified repairs in that bin.

**Area Under the Receiver Operating Characteristic (AUROC).** AUROC measures how often a randomly selected verified repair receives higher confidence than a randomly selected unverified attempt. A value of one means perfect ordering; 0.5 corresponds to chance.

\[
\text{AUROC} =
\frac{1}{n_+n_-}
\sum_{i:V_i=1}
\sum_{j:V_j=0}
\left[
\mathbf{1}(P_i>P_j)
+\frac{1}{2}\mathbf{1}(P_i=P_j)
\right]
\]

For an example with four attempts—confidence 0.9 with a verified repair, 0.9 with an unverified repair, 0.6 with a verified repair, and 0.3 with an unverified repair—the Brier score is approximately 0.27, ECE is 0.375, and AUROC is 0.625. AUROC cannot be computed if there are no verified repairs to compare with unverified attempts.

### 5.6 Latency and confidence intervals

The latency of each API call is recorded:

\[
L_i = 1000\left(t_i^{\text{response}}-t_i^{\text{request}}\right)\ \text{ms}
\]

Confidence intervals are calculated using a bootstrap that resamples whole vulnerabilities, because repeated attempts on the same vulnerability are not independent.

### 5.7 Baselines

Two baselines are used:

- **VRR baseline:** the direct-prompting result reported in the Vul4Py paper, at most five out of one hundred. This is a reference point, not a direct comparison, because the models used in this study differ from those in the original work.
- **FAR baseline:** the always-claim model.

## 6. Methodology

The planned study follows five stages.

### 6.1 Input and prompt

A Vul4Py case is used to build a fixed prompt containing the vulnerable source code and vulnerability identifier. It does not include the fix, tests, or results. The same prompt template is used for every model.

### 6.2 Model request

A program running on an Amazon EC2 cloud server sends the prompt to the model's API over HTTPS. The model returns a JSON object containing the patch, yes-or-no claim, and confidence score.

### 6.3 Freeze the model output

Before any verification, the complete model response is saved. A SHA-256 hash is computed for each file, and the files are set to read-only. There are no retries or manual edits. This allows the original claim to be checked later and prevents it from being adjusted after seeing the results.

### 6.4 Independent verification

The hashes are checked first. The vulnerable code is copied, the patch is applied, and whether it applied is recorded. If it applies, the functional tests and then the security tests are run on the same patched copy.

If the patch does not apply, no tests are run and both test results are zero. If an external issue occurs, such as a timeout or environment error, the attempt is marked **incomplete** and excluded from the denominator.

The model never receives the verification results.

### 6.5 Classification and metrics

The three results determine whether a repair is verified. False assurance is calculated, each failed attempt is classified by failure type, and the study metrics are computed.

The output is frozen to make the evaluation independently auditable. Both functional and security tests are necessary because an exploit test alone cannot detect a patch that breaks the program. Incomplete verifications are kept separate so infrastructure problems are not attributed to the model and are not hidden.

## 7. Pilot results

The pilot evaluated one model, `gpt-6-luna`, on five cases with one attempt per case. The prompt included the vulnerable files modified by the real fix, and the model was asked for its confidence in its claim.

The model claimed success in all five cases, with confidence scores between 0.82 and 0.91. None of the repairs was verified. The mean request latency was approximately 22 seconds.

\[
\text{VRR} = \frac{0}{5} = 0\%
\qquad
\text{FAR} = \frac{5}{5} = 100\%
\qquad
\text{CR} = \frac{5}{5}
\]

The failures were divided into two groups:

- In three cases, the diff was malformed and the patch tool refused to apply it, so no tests ran.
- In two cases, the patch applied and functional tests passed, but the security tests still failed.

Because no attempt was verified, the calibration results reflect the model's overconfidence. The Brier score is the average of the squared confidence values, and ECE is approximately 0.88.

\[
\text{BS} =
\frac{0.91^2+0.87^2+0.88^2+0.91^2+0.82^2}{5}
\approx 0.77
\]

\[
\text{ECE} \approx
\frac{3}{5}(0.857)+\frac{2}{5}(0.91)
\approx 0.88
\]

AUROC cannot be computed because there are no verified repairs to compare against unverified attempts. Since the model claimed success in every case, its FAR is equal to the always-claim baseline.

### What the pilot demonstrates

The pilot shows that the dataset can be obtained, the pipeline runs end to end, a baseline model can be run, and the metrics can be computed. It does not establish a general rate because it contains only five cases, one model, and cases that were not selected at random. Also, three of the five failures concern format rather than repair content, so the results do not yet show whether the model generally overclaims or simply produces invalid diffs.

### Issues found during the pilot

1. The benchmark scan ran security tests inside the vulnerable folder and left the fix's tests there. In two cases, the evaluation then ran a security test during the functional run and reported a false failure. This was identified because the same test failed in both runs. After restoring the file and evaluating the same frozen patch again, the functional result passed. The model's output was not changed, and VRR and FAR remained the same.
2. The first evaluation of one case classified a corrupt patch as an incomplete verification because the code did not recognize the tool's error. The rule was corrected and the same frozen patch was evaluated again.
3. The prompt includes the full text of the files changed by the real fix. This tells the model where the problem is. The fix itself is not shown, but the localization hint is a limitation; an experiment without the hint is planned.
4. In one case where the patch applied, the failing security test reads the name of an internal variable. If that name comes from the real fix, an alternative valid patch could also fail. This still needs confirmation in the code. Therefore, the result indicates that the security test failed, not necessarily that the vulnerability remained.

## 8. Future work and experimental plan

The full study will use three models: `gpt-6-luna`, Claude Fable 5.1, and DeepSeek-V4-Pro. Up to thirty Vul4Py cases will be randomly selected from those with status `OK`, with two trials per model and case. This gives up to 180 attempts.

\[
N_{\text{total}} = M \times D \times R
\leq 3 \times 30 \times 2 = 180
\]

Here, \(M\) is the number of models, \(D\) the number of cases, and \(R\) the number of repetitions. The total is described as “up to” 180 because only some cases reach status `OK`, and some attempts may be incomplete.

The study will report VRR, FAR, and claim rate with confidence intervals, compare FAR with the always-claim baseline, report calibration, and classify each failure.

The planned additional experiments and evaluation changes are:

- Run an ablation without the localization hint to measure how much the model depends on being told where the problem is.
- Test a different patch format because most pilot failures involved diffs that did not apply.
- Ensure the vulnerable folder is checked and restored before each attempt.
- Validate how test return codes are interpreted.
- Count a refusal or an answer that cannot be parsed as a failed repair.

The full study will also ask for confidence as the probability that the patch passes the complete verification. In the pilot, confidence referred to the claim, so the two sets of confidence values will not be directly comparable.

## 9. Feasibility and reproducibility

### Resources

The study uses an Amazon EC2 instance with 30 GB of disk, AWS credits, and API access to the three models. Disk space was the main limitation during the pilot: it had to be expanded from 8 GB to 30 GB. The environment for each project is deleted when it is no longer needed.

Based on pilot averages, 180 attempts would use approximately 900,000 input tokens and 400,000 output tokens. Actual usage depends on the model, and the cost has not been calculated. At the pilot's average latency, the API calls alone would take about one hour; total verification time has not yet been measured.

### Schedule

1. Fix the evaluation and complete the scripts by **[date]**.
2. Select and scan the cases by **[date]**.
3. Generate and evaluate all attempts by **[date]**.
4. Analyze the results by **[date]**.
5. Write the final paper by **[date]**.

### Reproducibility

The repository contains a README with installation and execution commands, the scripts, and an `evidence` folder with every frozen response, patch, evaluation, and test log. The hashes allow others to check that nothing was modified. The paper follows the MDPI format and includes the repository link.
