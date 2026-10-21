# Module Interfaces

## 1. Purpose

All modules must follow consistent input, output, and error-handling conventions so the orchestrator can integrate them without depending on implementation details.

## 2. Shared Finding Structure

Each assessment finding should contain:

- `check_id`: Stable identifier for the check.
- `title`: Short finding name.
- `status`: `PASS`, `FAIL`, `UNKNOWN`, or `ERROR`.
- `severity`: `INFO`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`, where applicable.
- `details`: Explanation of the result.
- `evidence`: Supporting observations, excluding unnecessary secrets.
- `remediation`: Recommended corrective action.

A `PASS` means the specific check passed; it does not mean the entire environment is secure.

## 3. Module Contracts

### Preflight

Each check accepts validated target and configuration data and returns one or more structured findings.

Checks must distinguish a confirmed failure from an inconclusive result. Network errors must not be reported as successful security checks.

### Coercion

Coercion methods must accept an explicitly scoped target and validated options. They must not select additional targets independently.

### Relay

Relay operations must accept the configured relay targets and validated options. They must not infer or expand the target list.

### Reporting

The reporting layer accepts findings and produces a readable report. It must not rerun checks or modify the original evidence.

### Utilities

Shared utilities should have narrow responsibilities, documented arguments, predictable return values, and clear error behavior.

## 4. Error Handling

- Use documented exceptions for unrecoverable module failures.
- Return `UNKNOWN` when a check cannot reach a reliable conclusion.
- Use `ERROR` for an operation that failed unexpectedly.
- Never convert exceptions or missing evidence into a successful result.
- Avoid logging credentials, tokens, or other sensitive values.

## 5. Integration Rules

- Agree on function signatures before implementing cross-module calls.
- Use shared data structures rather than module-specific dictionaries with inconsistent fields.
- Keep CLI argument parsing inside the CLI layer.
- Keep terminal formatting inside the reporting or presentation layer.
- Add unit tests for each public module interface.

## 6. Interface Changes

Changes to shared structures or public function signatures must be discussed with the project lead and documented before dependent modules are updated.

---

## 7. Coercion Module Interface

This section describes the specific contract that every coercion module must follow.
It reflects the code in `coercion/base.py` and `coercion/example.py`.

### 7.1 What a coercion module is

A coercion module is a self-contained piece of code that attempts one specific
technique against one explicitly specified target. It does not choose its own
target. It does not take on more than one responsibility. When it finishes, it
returns a `CoercionResult` describing exactly what happened.

### 7.2 The CoercionModule class

Every coercion module must inherit from `CoercionModule` (defined in
`coercion/base.py`). Inheriting means your module agrees to follow the rules
that `CoercionModule` sets out.

Your module must provide these three things:

| Name          | Type     | What it is                                                  |
|---------------|----------|-------------------------------------------------------------|
| `name`        | `str`    | A unique, short identifier for this module (e.g. `"PrinterBug"`). Used by the registry to look up and log modules. Must not be empty. |
| `description` | `str`    | A short, plain-English explanation of what the module does. |
| `run(target)` | method   | The function that does the work. Accepts one argument — the target hostname or IP address — and returns a `CoercionResult`. |

**Rules for `run(target)`:**

- `target` must be a non-empty string. Validate it at the top of `run()` and
  raise `ValueError` if it is not, so the caller receives a clear error instead
  of a confusing crash later.
- `run()` must always return a `CoercionResult`. It must never return `None` or
  raise an unhandled exception silently.
- `run()` must never expand the scope beyond the target it was given. It must
  not connect to other machines or discover additional targets on its own.

### 7.3 The CoercionResult dataclass

`CoercionResult` is the container that holds the outcome of one module run.
Think of it as a standardised form that every module fills in the same way,
so the reporting layer can read any result without needing to know which module
produced it.

| Field       | Type             | What it means                                                       |
|-------------|------------------|---------------------------------------------------------------------|
| `technique` | `str`            | The name of the technique or module that produced this result. Must match the module's `name`. Must be a non-empty string. |
| `target`    | `str`            | The target that was assessed. Must be a non-empty string.           |
| `success`   | `True`, `False`, or `None` | The outcome. See the status table below.              |
| `detail`    | `str`            | A plain-English explanation of what happened. May be empty.         |

**Status values for `success`:**

| Value   | Display label | Meaning                                                          |
|---------|---------------|------------------------------------------------------------------|
| `True`  | `SUCCESS`     | The module verified its intended outcome occurred.               |
| `False` | `FAILURE`     | The module verified its intended outcome did NOT occur.          |
| `None`  | `UNKNOWN`     | The outcome could not be determined (e.g. placeholder module, inconclusive result, or network issue). |

`CoercionResult` validates its own fields when created. If you pass an invalid
value, it raises a `ValueError` with a clear message. The validation rules are:

- `technique` must be a non-empty string (not `None`, not an integer, not
  whitespace only).
- `target` must be a non-empty string (same rules as `technique`).
- `success` must be exactly `True`, `False`, or `None`. Integers such as `1`
  and `0` are not accepted, even though Python considers `1 == True`.
- `detail` has no restriction. An empty string is allowed.

### 7.4 Development requirements for coercion modules

- **Do not report success without evidence.** If your module cannot confirm the
  outcome, set `success=None`. Never guess or assume.
- **Validate `target` early.** Check that `target` is a non-empty string at
  the top of `run()` before doing anything else.
- **Do not invent results.** The example module always returns `success=None`
  with a fixed detail message. A real module must reflect what actually happened.
- **Keep the example module non-operational.** `coercion/example.py` must never
  attempt network activity or real coercion. It exists only for testing and
  demonstration.
- **Test with mocked dependencies.** Do not require a live Active Directory
  environment to run unit tests. Use mock objects to simulate network responses.
- **Follow authorization and scope controls.** Only operate against explicitly
  specified, authorized targets. See the SRS and authorization notice for details.

---

## 8. How to Add a New Coercion Module

This section walks you through creating a new module from scratch.
Follow these steps in order.

**Step 1 — Create a new file in the `coercion/` folder.**

Name it after your technique, in lowercase with underscores, for example:
`coercion/printer_bug.py`.

**Step 2 — Import the base classes.**

```python
from coercion.base import CoercionModule, CoercionResult
```

**Step 3 — Define your class.**

Your class must inherit from `CoercionModule`. Set `name` and `description`
as class-level attributes. `name` must be unique across all modules.

```python
class PrinterBugModule(CoercionModule):
    name = "PrinterBug"
    description = "Attempts to trigger authentication via the MS-RPRN printer notification."
```

**Step 4 — Implement the `run` method.**

Validate `target` first, then do the work, then return a `CoercionResult`.
Set `success` only when you have actual evidence. Use `None` when unsure.

```python
    def run(self, target: str) -> CoercionResult:
        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must be a non-empty string")

        # --- your technique logic goes here ---
        # outcome = attempt_printer_bug(target)

        return CoercionResult(
            technique=self.name,
            target=target,
            success=None,   # replace with True or False once you have evidence
            detail="Replace this with a description of what actually happened.",
        )
```

**Step 5 — Write tests.**

Add a test file in `tests/` that covers at minimum:
- A valid run returns a `CoercionResult` with the correct `technique` and `target`.
- Passing an empty or invalid `target` raises `ValueError`.
- The module does not attempt network activity when `target` is invalid.

Use mocks to simulate the network — never require a live environment.

**Step 6 — Register the module** (if the project has a registry).

Follow the registry documentation once it is published. Until then, confirm
with the project lead how new modules are loaded.

**Quick reference checklist:**

- [ ] Class inherits from `CoercionModule`
- [ ] `name` is set, unique, and non-empty
- [ ] `description` is set
- [ ] `run()` validates `target` before doing anything else
- [ ] `run()` always returns a `CoercionResult`
- [ ] `success` is only `True` when there is actual evidence
- [ ] Tests are written and passing
- [ ] Module does not expand beyond the given target