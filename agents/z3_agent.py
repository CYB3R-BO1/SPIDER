from z3 import *
from typing import Dict, Any


class Z3Agent:
    """
    Lightweight symbolic solver for branch feasibility and expression solving.
    Supports simple arithmetic + comparison expressions.
    """

    def _parse_expr(self, expr: str, vars: Dict[str, Any]):
        """
        Convert a simple Python-like expression to a Z3 expression.
        Example: "x + 5 == 10"
        """
        # Create Z3 Int variables for unknown identifiers
        tokens = expr.replace("==", " ==").replace("!=", " !=").split()
        for tok in tokens:
            if tok.isidentifier() and tok not in vars:
                vars[tok] = Int(tok)

        # Unsafe eval is prevented by controlling globals
        return eval(expr, {"__builtins__": None}, vars)

    def check_branch_feasible(self, expr: str) -> bool:
        vars = {}
        z3expr = self._parse_expr(expr, vars)
        solver = Solver()
        solver.add(z3expr)
        return solver.check() == sat

    def solve_expression(self, expr: str) -> Dict[str, int]:
        vars = {}
        z3expr = self._parse_expr(expr, vars)
        solver = Solver()
        solver.add(z3expr)

        if solver.check() != sat:
            return {}

        model = solver.model()
        return {str(v): model[vars[v]].as_long() for v in vars if model[vars[v]]}
