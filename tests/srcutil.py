#!/usr/bin/env python3
"""Read a shipped file's CODE, without its comments and docstrings.

Why this exists: six separate checks in this suite went red because they
searched a source file for a string that only appeared in a COMMENT explaining
why the old, defective version was wrong. A substring search cannot tell a
defect from its own post-mortem, and the failure mode is the bad one -- it
fails on refactors (noise) and passes on regressions (a defect reintroduced
inside a comment-free line still matches whatever the check expected).

Two rules follow from that, and this module exists to make the first cheap:

  1. When a check MUST look at source text, look at code_only(path) so prose
     cannot trigger it.
  2. Prefer not to look at source text at all. Driving the function and
     asserting what it does survives every rename; asserting that a particular
     call appears on a particular line does not. Several checks here were
     converted from the second kind to the first after the shared helpers
     moved and the greps followed them around.

String LITERALS are kept: a message the tool prints, or an env-var name it
reads, is real behaviour and a legitimate thing to assert on. Only comments and
docstrings -- the two places explanation lives -- are removed.
"""
import ast
import io
import tokenize


def code_only(path: str) -> str:
    """Source with comments and docstrings blanked, line numbers preserved.

    Line structure is kept so a caller can still slice by line and get the
    same offsets it would from the raw file.
    """
    src = open(path, encoding="utf-8").read()
    lines = src.splitlines(keepends=True)

    # 1. comments, via tokenize (it knows a '#' inside a string is not one)
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(src).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return src                      # unparseable: better raw than wrong
    cuts = []
    for tok in toks:
        if tok.type == tokenize.COMMENT:
            cuts.append((tok.start, tok.end))

    # 2. docstrings, via the AST -- the leading string expression of a module,
    #    function or class. Any other string literal is left alone, because it
    #    is behaviour the tool exhibits rather than prose about it.
    try:
        tree = ast.parse(src)
    except SyntaxError:
        tree = None
    if tree is not None:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Module, ast.FunctionDef,
                                     ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            body = getattr(node, "body", None)
            if not body:
                continue
            first = body[0]
            if (isinstance(first, ast.Expr)
                    and isinstance(first.value, ast.Constant)
                    and isinstance(first.value.value, str)):
                cuts.append(((first.lineno, first.col_offset),
                             (first.end_lineno, first.end_col_offset)))

    # Blank each span, keeping newlines so line numbers do not shift.
    out = list(lines)
    for (sl, sc), (el, ec) in cuts:
        for ln in range(sl, el + 1):
            i = ln - 1
            if i >= len(out):
                continue
            line = out[i]
            nl = "\n" if line.endswith("\n") else ""
            body = line[:-1] if nl else line
            a = sc if ln == sl else 0
            b = ec if ln == el else len(body)
            a = min(a, len(body)); b = min(b, len(body))
            out[i] = body[:a] + (" " * max(0, b - a)) + body[b:] + nl
    return "".join(out)


def fail_loudly_on_crash(counters, label="suite"):
    """Make an unhandled exception print a RED result instead of no result.

    WHY: mutation_sweep scores a suite by parsing "N passed, M failed" out of
    its output, and its own header says a crash "prints no RESULT line, and a
    crashed suite proves nothing about its checks. Those score NO-RESULT, never
    CAUGHT". That is the right rule, and it means any mutation that makes a
    suite DIE rather than fail is recorded as a SURVIVOR.

    It has happened three times in this codebase:

      * test_dag_entry: a spread check called split_btc_amount directly, a
        mutation routed every split into its ValueError, and the file died --
        turning [17] from CAUGHT/RED(32) into SURVIVED/NO-RESULT and silently
        disarming 32 working checks;
      * test_units: `min(_amts)` on an empty list when a mutation made
        compute_fanout_amounts refuse everything, after two checks had already
        gone red;
      * test_units again, twenty lines later, on PeelBudgetError from the same
        mutation.

    Guarding each call site is whack-a-mole and the third one proves it. This
    guards the OUTCOME instead: whatever kills the file, the RESULT line still
    prints and it counts the crash as a failure, so a crash can never be read
    as green and can never be read as absent.

    `counters` is a zero-argument callable returning (passed, failed, names) so
    the live totals are read at exit rather than captured now.
    """
    import atexit
    import sys as _sys
    import traceback as _tb

    state = {"finished": False}

    def _done():
        state["finished"] = True

    def _at_exit():
        if state["finished"]:
            return
        exc = _sys.exc_info()[1]
        passed, failed, names = counters()
        print(f"\n  [!] {label} DIED before finishing: "
              f"{type(exc).__name__ if exc else 'unexpected exit'}")
        if exc is not None:
            _tb.print_exc()
        print(f"\nRESULT: {passed} passed, {failed + 1} failed")
        print("FAILED:", list(names) + [f"{label} crashed before completing"])

    atexit.register(_at_exit)
    return _done
