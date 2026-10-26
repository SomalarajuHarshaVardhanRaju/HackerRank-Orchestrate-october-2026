# Usage Report

HackerRank Orchestrate (October 2026) — Ghost Data Still Exists

## 1. Full-Dataset Run Summary

- **Execution Command:** `python code/main.py --mode full`
- **Output File:** `output.csv` (repository root)
- **Total Requests Evaluated:** 518 evaluation requests (`case_33` through `case_550`)
- **Status Counts:** 389 `INCOMPLETE`, 120 `COMPLETE`, 9 `NOT_APPLICABLE`
- **Output Validation:** 0 errors (100% schema, chronological cutoff, and reference checks passed)

---

## 2. Model & Token Usage Metrics

The solution operates as a high-performance, deterministic algorithmic agent written in Python that processes SQLite snapshots, JSON exports, syslog traces, PDF documents, and activity streams without requiring remote LLM inference calls at runtime.

| Measure | Final Full-Dataset Run |
|---|---:|
| Model Provider | Local Deterministic Runtime (Python 3) |
| Model Name | `code/main.py` Deterministic Audit Engine |
| Total Model Calls | 0 |
| Total Input Tokens | 0 |
| Total Output Tokens | 0 |
| Total Tokens | 0 |
| Average Tokens per Request | 0.00 |
| Estimated Cost per Request | $0.00 |
| **Total Estimated Model Cost** | **$0.00** |

---

## 3. Operational Performance & Resource Consumption

- **Total Execution Time (518 Cases):** ~8.4 seconds
- **Throughput:** ~61.6 requests/second
- **Memory Footprint:** Peak < 120 MB RAM
- **Deterministic Reproducibility:** 100% reproducible across runs with identical SHA-256 output hash.
