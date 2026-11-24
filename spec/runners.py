"""How each kind of proof is run.

Each returns (status, detail): "pass" (the proof holds), "fail" (the tool ran and
found the rule broken) or "error" (the tool did not run properly). An error is
never a pass, and never counts as catching a mutant.
"""
import os, re, shutil, subprocess

TLA_JAR = os.environ.get("TLA_JAR", os.path.expanduser("~/.local/share/tla/tla2tools.jar"))


def _java():
    if os.environ.get("TLA_JAVA"):
        return os.environ["TLA_JAVA"].split()
    for cmd in (["java"], ["mise", "x", "java@temurin-21", "--", "java"]):
        try:
            if subprocess.run(cmd + ["-version"], capture_output=True).returncode == 0:
                return cmd
        except FileNotFoundError:
            pass
    return ["java"]


def _run(cmd, cwd, timeout, env=None):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return None, "timed out"
    except FileNotFoundError as e:
        return None, f"not installed: {e.filename}"


def _last(out):
    lines = [l for l in out.strip().splitlines() if l.strip()]
    return lines[-1] if lines else "nothing printed"


def proverif(spec_dir, model, timeout=1800):
    code, out = _run(["proverif", "-lib", "protocol/common.pvl", f"protocol/{model}.pv"], spec_dir, timeout)
    results = [l for l in out.splitlines() if l.startswith("RESULT")]
    if code is None or code != 0 or not results:
        return "error", f"{model}: ProVerif did not finish: {_last(out)}"
    bad = [r for r in results if not r.endswith(" is true.")]
    if bad:
        return "fail", f"{model}: {bad[0]}"
    return "pass", f"{model}: {len(results)} of {len(results)} properties proved"


def tlc(spec_dir, only=None, timeout=3600):
    meta = os.path.join(spec_dir, "ledger", ".tlc")
    cmd = _java() + ["-XX:+UseParallelGC", "-cp", TLA_JAR, "tlc2.TLC", "-workers", "auto",
                     "-deadlock", "-metadir", meta, "-config", "Ledger.cfg", "Ledger.tla"]
    code, out = _run(cmd, os.path.join(spec_dir, "ledger"), timeout)
    shutil.rmtree(meta, ignore_errors=True)
    violated = re.findall(r"Invariant (\w+) is violated", out)
    if "Model checking completed. No error has been found." in out:
        # The last count is the final one; earlier lines are progress reports.
        states = re.findall(r"([\d,]+) distinct states found, 0 states left on queue", out)
        return "pass", f"ledger: every rule holds in all {states[-1] if states else '?'} reachable states"
    if violated:
        note = "" if not only or only in violated else f" (expected {only})"
        return "fail", f"ledger: {violated[0]} broken{note}"
    return "error", f"ledger: TLC did not finish: {_last(out)}"


def kani(root, harness, target_dir=None, timeout=7200):
    env = dict(os.environ)
    if target_dir:
        env["CARGO_TARGET_DIR"] = target_dir
    cmd = ["cargo", "kani", "-p", "unlinkable-inference", "--no-default-features",
           "--harness", f"proofs::{harness}", "--exact"]
    code, out = _run(cmd, root, timeout, env)
    if "VERIFICATION:- SUCCESSFUL" in out:
        return "pass", f"{harness}: proved"
    if "VERIFICATION:- FAILED" in out:
        failed = re.findall(r'Status: FAILURE\n\s+- Description: "([^"]+)"', out)
        return "fail", f"{harness}: broken: {failed[0] if failed else 'see Kani output'}"
    return "error", f"{harness}: Kani did not finish: {_last(out)}"


def exhaustive(root, rule=None, target_dir=None, timeout=1800):
    """lib/examples/exhaustive_proofs.rs: every amount in range, one by one."""
    env = dict(os.environ)
    if target_dir:
        env["CARGO_TARGET_DIR"] = target_dir
    cmd = ["cargo", "run", "-q", "--release", "-p", "unlinkable-inference", "--no-default-features",
           "--example", "exhaustive_proofs"]
    code, out = _run(cmd, root, timeout, env)
    broken = [l for l in out.splitlines() if l.startswith("BROKEN")]
    oks = [l for l in out.splitlines() if l.startswith("ok ")]
    if broken:
        hit = [l for l in broken if rule and l.startswith(f"BROKEN {rule}:")]
        return "fail", (hit or broken)[0] + ("" if not rule or hit else f" (expected {rule})")
    if code == 0 and oks:
        return "pass", "; ".join(oks)
    return "error", f"exhaustive proofs did not finish: {_last(out)}"
