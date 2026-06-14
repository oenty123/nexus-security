#!/usr/bin/env python3
"""Nexus Core CLI — базовый анализ безопасности (MIT)."""
import argparse, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from engine import analyze

def main(argv=None):
    p = argparse.ArgumentParser(description="Nexus Core — SAST (бесплатная версия)")
    p.add_argument("target")
    p.add_argument("--format", choices=["text","json"], default="text")
    p.add_argument("--depth", type=int, default=2, choices=[1,2,3])
    args = p.parse_args(argv)
    path = Path(args.target)
    if not path.exists():
        print(f"Файл не найден: {path}", file=sys.stderr); return 2
    code = path.read_text(encoding="utf-8", errors="ignore")
    r = analyze(code, str(path), args.depth)
    if args.format == "json":
        print(json.dumps(r.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(f"{path}: {r.grade} ({r.score}/100), {len(r.findings)} проблем")
        for f in r.findings:
            print(f"  [{f.severity.upper():8}] строка {f.line}: {f.title} [{f.cwe}]")
        if r.findings:
            print("\n→ Продвинутый анализ (dataflow, кросс-модуль, авто-фикс,")
            print("  compliance-отчёты) доступен в Nexus Enterprise:")
            print("  https://nexus-security.io/enterprise")
    return 0

if __name__ == "__main__":
    sys.exit(main())
