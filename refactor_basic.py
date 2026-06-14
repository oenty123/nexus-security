"""
refactor_basic.py — базовый рефакторинг (Nexus Core, MIT).

Минимальный набор детерминированных AST-трансформаций:
  - if x == True  → if x
  - if x == False → if not x
  - len(x) > 0    → x
  - not x in y    → x not in y

Это БАЗОВАЯ версия. Продвинутый рефакторинг (30+ трансформаций,
извлечение функций, упрощение вложенности, dead-code elimination,
переименование, мультиязычность) — в Nexus Enterprise.
"""

from __future__ import annotations

import ast
from typing import List, Tuple


class BasicRefactor(ast.NodeTransformer):
    """4 безопасных трансформации читаемости."""

    def __init__(self) -> None:
        self.changes: List[str] = []

    def visit_Compare(self, node: ast.Compare) -> ast.AST:
        self.generic_visit(node)
        if (len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq)
                and len(node.comparators) == 1):
            comp = node.comparators[0]
            if isinstance(comp, ast.Constant) and comp.value is True:
                self.changes.append("if x == True → if x")
                return node.left
            if isinstance(comp, ast.Constant) and comp.value is False:
                self.changes.append("if x == False → if not x")
                return ast.UnaryOp(op=ast.Not(), operand=node.left)
        # len(x) > 0 → x
        if (len(node.ops) == 1 and isinstance(node.ops[0], ast.Gt)
                and isinstance(node.left, ast.Call)
                and isinstance(node.left.func, ast.Name)
                and node.left.func.id == "len"
                and len(node.left.args) == 1
                and isinstance(node.comparators[0], ast.Constant)
                and node.comparators[0].value == 0):
            self.changes.append("len(x) > 0 → x")
            return node.left.args[0]
        return node

    def visit_UnaryOp(self, node: ast.UnaryOp) -> ast.AST:
        self.generic_visit(node)
        if (isinstance(node.op, ast.Not) and isinstance(node.operand, ast.Compare)
                and len(node.operand.ops) == 1
                and isinstance(node.operand.ops[0], ast.In)):
            self.changes.append("not x in y → x not in y")
            return ast.Compare(left=node.operand.left, ops=[ast.NotIn()],
                               comparators=node.operand.comparators)
        return node


def refactor_basic(code: str) -> Tuple[str, List[str]]:
    """Применяет базовые трансформации. Возвращает (новый_код, изменения)."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return code, []
    refactor = BasicRefactor()
    new_tree = refactor.visit(tree)
    ast.fix_missing_locations(new_tree)
    if not refactor.changes:
        return code, []
    try:
        return ast.unparse(new_tree), refactor.changes
    except Exception:
        return code, []


if __name__ == "__main__":
    code = "if flag == True:\n    if len(items) > 0:\n        if not x in seen:\n            go()"
    result, changes = refactor_basic(code)
    print(f"Базовый рефакторинг: {len(changes)} изменений")
    for c in changes:
        print(f"  • {c}")
    print("\n" + result)
    print("\n→ Продвинутый рефакторинг (30+ правил) в Nexus Enterprise")
