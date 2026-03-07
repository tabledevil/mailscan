# TODO: Event-Driven Password Retry for Encrypted Objects

## Goal
Implement a global, event-driven password retry workflow so encrypted/decryptable objects (starting with ZIP) can be retried automatically whenever a new password is discovered anywhere in the analysis tree.

Primary outcome: encrypted ZIPs that initially fail to open can be unlocked later after passwords are extracted from text/email content.

## Design Decisions (Locked)
- Use a global broker module at `Utils/password_broker.py`.
- Use event-driven matching in both directions:
  - Password discovered first -> broker immediately tries all pending encrypted items.
  - Encrypted item discovered first -> item is registered as pending, and broker immediately tries all known passwords.
- Add reporting on both sides when a retry succeeds:
  - On unlocked item: decrypted/unlocked report.
  - On password producer side: report that discovered password unlocked a pending item.
- Do **not** add `Structure.invalidate_children()`.
  - Not needed because `Structure.get_children()` caches the same mutable `childitems` list reference, so appended children are naturally visible.

## Scope (This Iteration)
- In scope:
  - Global broker implementation.
  - ZIP integration for deferred retries.
  - Password producer integration in `PlainTextAnalyzer` (regex password scan + IOC passwords).
  - Broker reset during top-level cache clear.
- Out of scope:
  - PDF/7z/Office decryptors (future integrations can use same broker API).
  - Network enrichment.
  - TUI changes.

## Files To Create / Modify

### New
- `Utils/password_broker.py`

### Modify
- `Analyzers/ZipAnalyzer.py`
- `Analyzers/PlainTextAnalyzer.py`
- `structure.py` (only to clear broker state with Structure cache)

## Implementation Tasks

1. Create `Utils/password_broker.py`
- Add dataclass for pending encrypted targets:
  - `struct_ref`: weakref to pending `Structure` node.
  - `description`: human-readable target label.
  - `try_password(password: str) -> bool`: callback provided by analyzer.
- Add class `PasswordBroker` with class-level state:
  - `_passwords`: discovered passwords in discovery order.
  - `_pending`: map keyed by pending object identity.
  - `_used_links`: optional dedup map for reporting producer->target usage.
- Public API:
  - `register_password(password: str, source_struct=None) -> None`
  - `register_pending(struct, description: str, try_password_cb) -> bool`
  - `get_passwords() -> list[str]`
  - `clear() -> None`
- Behavior:
  - Deduplicate passwords.
  - On `register_password`, immediately try this password on all pending targets.
  - On `register_pending`, immediately try all known passwords against that target.
  - Remove pending target once unlocked.
  - Use weakrefs to avoid pinning `Structure` objects in memory.
  - Add robust logging with masked password output.

2. Update `Analyzers/ZipAnalyzer.py`
- Keep current static password list (`infected`, variants) as first-pass attempts.
- For encrypted ZIPs where built-in list fails:
  - Register a pending target via `PasswordBroker.register_pending(...)`.
  - Provide closure callback that:
    - Reopens ZIP from `self.struct.rawdata`.
    - Tests candidate password (`setpassword`, `testzip` or read attempt).
    - On success, extracts children into `self.childitems`.
    - Creates report(s): password used + decrypted/unlocked status.
    - Returns `True` on success, else `False`.
- If `register_pending` returns `True`, continue as resolved.
- If unresolved, keep current dead-end behavior but indicate waiting state in report.
- Ensure no duplicate child extraction if callback is invoked multiple times.

3. Update `Analyzers/PlainTextAnalyzer.py`
- On password candidates discovered by regex scan (`_scan_passwords`):
  - Register each candidate with broker via `PasswordBroker.register_password(...)`.
  - Keep existing report behavior.
- On IOC passwords (`_extract_iocs`, `iocs.passwords`):
  - Register each IOC password with broker.
- Add producer-side report entries when a discovered password unlocks pending content (via broker signaling or callback bookkeeping).

4. Update `structure.py`
- In `Structure.clear_cache()` add broker reset:
  - Import broker and call `PasswordBroker.clear()`.
- Keep existing cache clear behavior unchanged.

5. Reporting semantics
- Unlocked encrypted object report:
  - Severity: `HIGH` (encrypted object + in-band password is strong signal).
  - Include concise text that object was unlocked with discovered password.
- Password producer report:
  - Severity: `HIGH`.
  - Include which pending item was unlocked (description only, no plaintext password required).
- Avoid exposing plaintext password in high-level short output unless current style already does.

6. Robustness and edge cases
- Prevent duplicate pending registrations for same struct.
- Prevent repeat unlock handling for already-resolved targets.
- Handle stale weakrefs (garbage-collected structs) gracefully.
- Handle exceptions in callback without crashing analysis.
- Avoid infinite loops or recursive retry storms.

## Acceptance Criteria
- Encrypted ZIP with unknown password is registered as pending, not silently dropped.
- If password is discovered later in any analyzed text node, pending ZIP is retried automatically.
- On successful retry:
  - ZIP children are extracted and analyzed.
  - Unlocked ZIP node has clear HIGH-severity report.
  - Password source node has clear HIGH-severity "password used" report.
- `Structure.clear_cache()` clears both structure cache and password broker state.
- Existing non-encrypted ZIP behavior remains unchanged.

## Validation / Smoke Test Plan

1. Basic regression
- Run current sample analysis on benign/non-encrypted ZIP.
- Confirm behavior unchanged.

2. Target scenario (infected sample)
- Run analysis on `samples/infected.zip`.
- Confirm password is extracted from text body (e.g. `stlRfdhpsk`).
- Confirm nested encrypted ZIP is unlocked automatically.
- Confirm newly unlocked child files appear in output tree.

3. Ordering scenarios
- Scenario A: password discovered before encrypted attachment.
- Scenario B: encrypted attachment discovered before password source.
- Confirm both directions work.

4. Output checks
- Verify both-side reporting (producer + consumer).
- Verify no duplicate child extraction on repeated retries.

## Suggested Commit Breakdown
- Commit 1: add broker module + structure clear integration.
- Commit 2: integrate broker with ZipAnalyzer pending/retry flow.
- Commit 3: integrate password producers in PlainTextAnalyzer + reporting polish.
- Commit 4: smoke test adjustments and minor fixes.

## Follow-ups (Next Iterations)
- Add broker consumers for encrypted PDF/7z/Office containers.
- Standardize password confidence scoring (regex context vs IOC extraction).
- Add dedicated tests for broker behavior and callback lifecycle.
- Consider redaction policy for password rendering across output formats.
