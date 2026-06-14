"""engine.py (Core) — базовый движок Nexus Core (MIT).

Бесплатно: 52 правила, taint внутри файла, секреты, подавление FP.
Enterprise (dataflow/CFG, кросс-модуль, compliance, autofix, веб-платформа):
https://nexus-security.io/enterprise
"""
from __future__ import annotations
import dataclasses, re
from pathlib import Path
from typing import List
from rules_security import rules_for_language
from engine_taint import analyze_interprocedural


@dataclasses.dataclass
class Finding:
    rule_id: str; title: str; severity: str; cwe: str; category: str
    file: str; line: int; col: int = 0; snippet: str = ""; desc: str = ""
    fix_before: str = ""; fix_after: str = ""; confidence: str = "medium"; source: str = "rule"
    def to_dict(self): return dataclasses.asdict(self)


SEVW = {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}


def detect_language(filename: str) -> str:
    return {".py":"python",".js":"javascript",".ts":"typescript",".go":"go",
            ".java":"java",".php":"php",".rb":"ruby",".cs":"csharp"}.get(
            Path(filename).suffix.lower(), "unknown")


def analyze(code: str, filename: str = "unknown", depth: int = 2):
    language = detect_language(filename)
    findings: List[Finding] = []
    lines = code.splitlines()

    if language == "python":
        try:
            for t in analyze_interprocedural(code, filename):
                findings.append(Finding(t.rule_id, t.title, t.severity, t.cwe,
                    "taint", filename, t.line, t.col, t.snippet,
                    f"Taint: {' → '.join(t.flow)}", "", t.fix, t.confidence, "taint"))
        except Exception:
            pass

    taint_lines = {f.line for f in findings}
    is_test = bool(re.search(r"test_|_test\b|/tests?/", filename, re.I))
    for rule in rules_for_language(language):
        if depth == 1 and rule.severity in ("low", "medium"):
            continue
        for m in rule.pattern.finditer(code):
            ln = code[:m.start()].count("\n") + 1
            if ln in taint_lines:
                continue
            snippet = lines[ln-1].strip() if ln <= len(lines) else ""
            if snippet.startswith(("#","//","*")):
                continue
            # фильтр самосканирования: строки-определения правил — не уязвимости
            if any(mk in snippet for mk in ("_rx(", "SecurityRule(", "re.compile(",
                    "fix_before", "fix_after", "CWE-", "category=", "rule_id=")):
                continue
            if is_test and depth < 3 and rule.severity != "critical":
                continue
            findings.append(Finding(rule.id, rule.title, rule.severity, rule.cwe,
                rule.category, filename, ln, 0, snippet[:120], rule.description,
                rule.fix_before, rule.fix_after, rule.confidence, "rule"))

    # секреты
    for name, pat, sev in [
        ("AWS Key", re.compile(r'AKIA[0-9A-Z]{16}'), "critical"),
        ("GitHub Token", re.compile(r'gh[pousr]_[0-9a-zA-Z]{36,}'), "critical"),
        ("Private Key", re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'), "critical"),
    ]:
        for m in pat.finditer(code):
            ln = code[:m.start()].count("\n") + 1
            findings.append(Finding(f"SECRET-{name.replace(' ','-').upper()}",
                f"Секрет: {name}", sev, "CWE-798", "secrets", filename, ln, 0,
                "***REDACTED***", "Ротируйте секрет", "", "os.getenv(...)", "high", "secret"))

    seen=set(); uniq=[]
    for f in findings:
        k=(f.line,f.cwe,f.category)
        if k in seen: continue
        seen.add(k); uniq.append(f)
    findings=uniq
    order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
    findings.sort(key=lambda f: (order.get(f.severity,5), f.line))
    score = max(0, 100 - sum(SEVW.get(f.severity,0) for f in findings))
    grade = "A" if score>=90 else "B" if score>=75 else "C" if score>=55 else "D" if score>=35 else "F"

    return type("CoreResult", (), {
        "filename": filename, "language": language, "findings": findings,
        "score": score, "grade": grade,
        "to_dict": lambda self=None: {
            "filename": filename, "language": language, "score": score,
            "grade": grade, "tier": "core",
            "findings": [f.to_dict() for f in findings],
            "summary": {"total": len(findings)},
        }
    })()
