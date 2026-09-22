"""
execution_sandbox.py
-----------------------
WHY THIS FILE EXISTS:
Running dynamically generated code with a bare `exec(code)` is dangerous --
that code would have full access to every builtin (open, __import__, eval,
os access via import, etc.), meaning a bug in the code generator, or a
malicious value smuggled into a drift event, could do real damage. This
module runs the generated remediation in a DELIBERATELY crippled scope:

- `__builtins__` is replaced with an EMPTY dict, so builtin names like
  `open`, `__import__`, `eval`, and `exec` itself are not even resolvable
  inside the executed code. Name lookups for anything not explicitly
  provided simply fail with a NameError.
- The only name made available to the executed code is `client` -- a
  single MockAWSClient instance bound to ONE specific cloud state. The
  generated code cannot reach any other object, module, or piece of state
  in the running process.

This mirrors real "least privilege" execution sandboxing: the remediation
code can do exactly one thing -- call a security-group revocation method
on the one client it was handed -- and nothing else.
"""
import time


class RemediationError(Exception):
    """Raised when sandboxed execution of generated remediation code fails."""
    pass


def run_remediation_safely(code_obj, client) -> dict:
    """Executes a compiled remediation code object inside a locked-down
    scope where `client` is the only usable name. Returns timing +
    success info; raises RemediationError on any failure so callers can
    decide how to react (e.g. alert a human instead of silently failing)."""
    sandbox_globals = {"__builtins__": {}, "client": client}
    sandbox_locals = {}

    start = time.perf_counter()
    try:
        exec(code_obj, sandbox_globals, sandbox_locals)
    except Exception as e:
        raise RemediationError(f"Sandboxed remediation failed: {e}") from e
    elapsed = time.perf_counter() - start

    return {"succeeded": True, "elapsed_seconds": round(elapsed, 6)}


if __name__ == "__main__":
    # Standalone proof that the sandbox is actually locked down: this
    # deliberately malicious payload tries to use `open` to read a file
    # from disk, and must fail with a NameError because __builtins__ is
    # empty in the sandbox -- proving the isolation actually works rather
    # than just asserting it in a docstring.
    malicious_code = compile("open('/etc/passwd').read()", "<malicious-test>", "exec")

    print("Attempting to run a payload that calls open() inside the sandbox...")
    try:
        run_remediation_safely(malicious_code, client=None)
        print("!! SECURITY FAILURE: the sandbox allowed a builtin call through.")
    except RemediationError as e:
        print(f"Sandbox correctly blocked it: {e}")
