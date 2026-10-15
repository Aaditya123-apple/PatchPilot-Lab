# Benchmark

PatchPilot's rule engine is measured against public, labelled vulnerable-code datasets, and against the Python standard library as a large body of ordinary code.

```bash
python -m bench.fetch_datasets          # downloads SecurityEval and Bandit into bench/data/
python -m bench.evaluate --label mine   # writes bench/results/mine.json
```

## Datasets

| Dataset | What it is | How it's scored |
| --- | --- | --- |
| [SecurityEval](https://github.com/s2e-lab/SecurityEval) | 121 vulnerable Python samples covering 69 CWEs | **Detect:** any finding in the sample. **CWE match:** a finding with the labelled CWE, or a closely related one (for example CWE-79/80, CWE-327/328). |
| [Bandit examples](https://github.com/PyCQA/bandit/tree/main/examples) | 86 example files with the number of Medium/High issues Bandit's own tests expect | **File recall:** vulnerable files with at least one Medium+ finding. **Issue recall:** Medium+ findings found, capped at the expected count. |
| Python 3.12 standard library | 594 files, 278K lines, tests excluded | Medium+ alarms per 1,000 lines (a proxy for false-positive rate), throughput, crashes |

Every automatic fix produced on any of these files is also checked: it must parse, its diff must apply cleanly, public functions and classes must survive, the finding must actually stop firing, and no new finding may appear.

## Results

Static engine only (no model calls), same machine for both runs.

| Metric | Baseline (21 rules) | Now (58 rules, taint tracking) |
| --- | --- | --- |
| SecurityEval: detected | 16.5% | **80.2%** |
| SecurityEval: correct CWE | 12.4% | **69.4%** |
| SecurityEval: CWEs covered | 10 / 69 | **46 / 69** |
| Bandit: vulnerable files caught | 20.3% | **84.7%** |
| Bandit: issue recall | 14.6% | **60.3%** |
| Bandit: clean examples with alarms | 3 / 27 | **2 / 27** |
| Stdlib: Medium+ alarms per KLOC | 0.55 | **0.35** |
| Stdlib: throughput | 87 KLOC/s | 18–29 KLOC/s |
| Automatic fixes: invalid / regressing / overclaimed | 0 / 0 / 0 | 0 / 0 / 0 (258 fixes checked) |
| Crashes | 0 | 0 |

Throughput dropped because of import resolution and taint tracking; a 100K-line repository still scans in a few seconds. Raw results for every run are in `bench/results/`.

## Where PatchPilot and Bandit disagree on purpose

- **Constant strings.** `exec("...")` and `Markup(content)` where `content` is a hardcoded literal are not flagged: a string the developer wrote can't carry an injection. Bandit flags them, so `exec.py` and two `markupsafe_*` examples count as misses.
- **Severity of hardcoded passwords.** Bandit rates these Low; PatchPilot rates them High. That makes `hardcoded-passwords.py`, which Bandit's tests treat as having no Medium+ issues, show up as an alarm.
- **`# nosec` and `# patchpilot: ignore`** suppress findings on that line, as in Bandit.

The other `mark_safe_secure.py` alarms are genuine false positives: a variable reassigned in several branches is treated conservatively.

## What's left for the model

Most remaining SecurityEval misses are logic flaws a pattern can't see: missing authentication (CWE-306), incorrect authorization (CWE-285), unchecked return values (CWE-252), race conditions, privilege handling (CWE-250/269/283) and similar. Those are the cases the Nemotron Scanner agent is meant to catch, and they haven't been measured here because the benchmark runs without an API key.

## Pressure testing

`tests/test_pressure.py` runs on every `pytest`:

- **Mutation fuzzing:** 600 randomly corrupted files (deleted, swapped and duplicated lines, garbage characters, null bytes, truncation, CRLF). The scanner, chunker, fixer and diff tools must never crash, chunks must cover every line, and any fix must parse and round-trip.
- **Fixer fuzzing:** 300 valid programs stitched from vulnerable snippets. Every automatic fix must parse, apply cleanly and keep public names.
- **Pathological inputs:** empty files, a byte-order mark, a null byte, 3,000 nested parentheses, a 30,000-term expression, a 500K-character line, 20,000 lines and mixed indentation.
- **Chaotic model:** a fake Nemotron that fails 20% of calls and otherwise returns garbage JSON, out-of-range lines, truncated or wrong-language code, prompt-injection text, half-deleted files and absurd confidence scores. The agent loop must finish every file, never ship code that doesn't parse or drops public functions, and never approve a patch that fails a hard check.
- **Load:** 300 files audited concurrently.
