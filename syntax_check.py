"""
syntax_check.py — проверка синтаксиса Python с диагностикой и авто-исправлением.

Находит синтаксические ошибки, даёт понятные сообщения и предлагает исправление
для частых случаев:
  - Отсутствие двоеребия после if/for/def/class
  - Несбалансированные скобки
  - Смешение табов и пробелов
  - Trailing запятые в неправильных местах
  - print как statement (Python 2 → 3)
  - Отсутствие отступа после блока

Безопасно: авто-исправление применяется только к однозначным случаям,
с проверкой что результат компилируется.
"""

from __future__ import annotations

import ast
import dataclasses
import re
from typing import List, Optional


@dataclasses.dataclass
class SyntaxIssue:
    line:       int
    col:        int
    message:    str
    suggestion: str
    fixable:    bool

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class SyntaxCheckResult:
    filename:   str
    valid:      bool
    issues:     List[SyntaxIssue]
    fixed_code: Optional[str] = None
    fix_applied: bool = False

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "valid": self.valid,
            "issues": [i.to_dict() for i in self.issues],
            "fix_applied": self.fix_applied,
        }


def check_syntax(code: str, filename: str = "unknown") -> SyntaxCheckResult:
    """Проверяет синтаксис и диагностирует ошибки."""
    issues: List[SyntaxIssue] = []

    try:
        ast.parse(code)
        return SyntaxCheckResult(filename, valid=True, issues=[])
    except SyntaxError as e:
        issue = _diagnose_syntax_error(e, code)
        issues.append(issue)
    except Exception as e:
        issues.append(SyntaxIssue(0, 0, f"Ошибка парсинга: {e}", "", False))

    # Дополнительная проверка табов/пробелов
    issues.extend(_check_indentation(code))

    return SyntaxCheckResult(filename, valid=False, issues=issues)


def _diagnose_syntax_error(e: SyntaxError, code: str) -> SyntaxIssue:
    """Превращает SyntaxError в понятное сообщение с предложением."""
    line = e.lineno or 0
    col = e.offset or 0
    msg = e.msg or "синтаксическая ошибка"
    lines = code.splitlines()
    line_text = lines[line - 1] if 0 < line <= len(lines) else ""

    suggestion = ""
    fixable = False

    # Отсутствие двоеточия
    if "expected ':'" in msg or (
        re.match(r"\s*(if|elif|else|for|while|def|class|try|except|finally|with)\b", line_text)
        and not line_text.rstrip().endswith(":")
    ):
        suggestion = "Добавьте двоеточие ':' в конце строки"
        fixable = True
    # Несбалансированные скобки
    elif "was never closed" in msg or "unexpected EOF" in msg:
        opens = line_text.count("(") + line_text.count("[") + line_text.count("{")
        closes = line_text.count(")") + line_text.count("]") + line_text.count("}")
        if opens > closes:
            suggestion = "Закройте открытую скобку"
            fixable = False
    # print как statement (Python 2)
    elif "Missing parentheses" in msg and "print" in msg:
        suggestion = "Используйте print() как функцию: print(...)"
        fixable = True
    # Невалидный отступ
    elif "unexpected indent" in msg:
        suggestion = "Уберите лишний отступ в начале строки"
        fixable = True
    elif "expected an indented block" in msg:
        suggestion = "Добавьте отступ — после двоеточия нужен блок кода"
        fixable = False
    else:
        suggestion = "Проверьте синтаксис в указанной строке"

    return SyntaxIssue(line, col, msg, suggestion, fixable)


def _check_indentation(code: str) -> List[SyntaxIssue]:
    """Проверяет смешение табов и пробелов."""
    issues: List[SyntaxIssue] = []
    has_tabs = False
    has_spaces = False
    for i, line in enumerate(code.splitlines(), 1):
        indent = len(line) - len(line.lstrip())
        prefix = line[:indent]
        if "\t" in prefix:
            has_tabs = True
        if "    " in prefix or (prefix and " " in prefix):
            has_spaces = True
    if has_tabs and has_spaces:
        issues.append(SyntaxIssue(
            0, 0, "Смешение табов и пробелов в отступах",
            "Используйте только пробелы (PEP 8): замените табы на 4 пробела", True,
        ))
    return issues


def auto_fix_syntax(code: str) -> SyntaxCheckResult:
    """
    Применяет авто-исправления для однозначных синтаксических ошибок.
    Каждое исправление проверяется: результат должен компилироваться лучше.
    """
    result = check_syntax(code)
    if result.valid:
        return result

    fixed = code

    # 1. Табы → 4 пробела
    if any("таб" in i.message.lower() for i in result.issues):
        fixed = fixed.expandtabs(4)

    # 2. print statement → print()
    fixed = re.sub(
        r"^(\s*)print\s+([^(\n][^\n]*)$",
        r"\1print(\2)",
        fixed,
        flags=re.MULTILINE,
    )

    # 3. Добавление двоеточий после управляющих конструкций
    lines = fixed.splitlines()
    for i, line in enumerate(lines):
        stripped = line.rstrip()
        if re.match(r"\s*(if|elif|else|for|while|def|class|try|except|finally|with)\b",
                    stripped):
            # Строка-заголовок блока без двоеточия и без продолжения
            if (not stripped.endswith(":") and not stripped.endswith("\\")
                    and "(" not in stripped.split("#")[0][-1:]
                    and not stripped.endswith(",")):
                # Проверяем, что скобки сбалансированы (не многострочный заголовок)
                if stripped.count("(") == stripped.count(")"):
                    lines[i] = stripped + ":"
    candidate = "\n".join(lines)

    # Проверяем, что исправление помогло
    try:
        ast.parse(candidate)
        return SyntaxCheckResult(
            result.filename, valid=True, issues=result.issues,
            fixed_code=candidate, fix_applied=True,
        )
    except SyntaxError:
        # Частичное исправление — возвращаем что есть
        try:
            ast.parse(fixed)
            return SyntaxCheckResult(
                result.filename, valid=True, issues=result.issues,
                fixed_code=fixed, fix_applied=True,
            )
        except SyntaxError:
            return SyntaxCheckResult(
                result.filename, valid=False, issues=result.issues,
                fixed_code=None, fix_applied=False,
            )


if __name__ == "__main__":
    broken = """def greet(name)
    print "Hello"
    if name == "admin"
        return True
"""
    print("=== Проверка ===")
    result = check_syntax(broken, "broken.py")
    print(f"Валиден: {result.valid}")
    for issue in result.issues:
        print(f"  Строка {issue.line}: {issue.message}")
        print(f"    → {issue.suggestion} (исправимо: {issue.fixable})")

    print("\n=== Авто-исправление ===")
    fixed = auto_fix_syntax(broken)
    print(f"Исправлено: {fixed.fix_applied}")
    if fixed.fixed_code:
        print(fixed.fixed_code)
