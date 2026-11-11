# Task relay

A small utility for running trusted, pinned tasks and returning results over authenticated channels. Uses Node.js built-in modules; no package installation is required.

The task workflow accepts an AES-256-GCM authenticated envelope bound to its repository and execution environment. Requests expire and claim a unique reference before execution. Git checkout verifies the complete commit ID. Optional private inputs have bounded sizes and pinned SHA-256 identities; API credentials are never forwarded to signed download URLs. Commands run with bounded time and captured output. Results and checksums are returned to a private destination; the workflow does not publish artifacts, caches, summaries, or test reports.

Run the utility's tests with `node --test test/*.test.mjs`.

Operators configure `EXECUTION_KEY` (64 lowercase hexadecimal characters), `SOURCE_TOKEN` (repository contents read), and `RESULT_TOKEN` (repository contents write). Limit credentials to the required repositories and grant access only to trusted maintainers. The destination must be private and owned by the same account as this repository. Results are draft releases, with a receipt, a compressed log, and optional files. An incomplete release or a missing receipt is never a successful result. Retain receipts and request claims until their request validity period has ended.

The utility accepts trusted code only. It is not a sandbox for hostile code. Command environments exclude workflow command channels and credentials; code still runs on the host VM. Do not enable runner or step debugging. Retries need a new request; uncertain API submissions are not retried automatically.

Repository ownership, workflow source, actor identity, selected runner, timing, and outcome remain visible. Hosting limits, billing eligibility, and applicable service terms must be checked before activation. This utility does not establish eligibility for free compute. Large files, external resources, platform-specific prerequisites, resource budgets, and workload acceptance remain the operator's responsibility.
