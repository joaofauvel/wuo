# Full feature upgrade preflight

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan step by step.

**Goal:** Let `wuo update` validate a Windows 11 feature upgrade offer and matching ISO, then perform a native keep-apps-and-data compatibility scan.

**Architecture:** The normal update scan discovers every category unless `--only` limits it. A dry run with `--feature-iso` can also match one full feature offer to its base build in Microsoft's release history. A native PowerShell process holds the verified ISO open, mounts it read-only, checks the installation image, invokes Setup with `/Compat ScanOnly`, and cleans up. The compatibility check runs before any future install-capable workflow.

**Tech stack:** Python 3.15, httpx, Beautiful Soup, Windows PowerShell, DISM, Windows Setup, pytest.

1. Write tests for incomplete and ambiguous offers, release build lookup, and rejection of unsuccessful native Setup results.
2. Write CLI tests proving there is no path from the feature check to ordinary staging or a committing Setup command. Validate explicit license acceptance and preview the requested rollback policy.
3. Implement the offer, media and native scan checks. Keep any feature-only failure independent of daily servicing.
4. Run Ruff, mypy and pytest. Exercise the Windows PowerShell path with fixtures, then use disposable Windows guests for native Setup and upgrade validation.

The feature remains a preview until the actual WinRE handoff and cold-restart failure paths have been demonstrated. Neither rollback policy arms a job during preflight.
