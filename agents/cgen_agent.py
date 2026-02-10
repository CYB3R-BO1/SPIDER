import re
from typing import Dict, List, Optional, Set, Tuple

from storage.graph_store import GraphStore


class CCodeGeneratorAgent:
    """
    Generates simplified C-like pseudocode.
    Responsibilities:
    - Convert IR and CFG structure into structured code blocks.
    - Simplify expressions using Z3 where possible.
    - Provide readable pseudocode for UI display.
    """

    def __init__(self, graph_store: GraphStore):
        self.g = graph_store

    def generate(self, func_addr: int) -> str:
        blocks = self.g.fetch_basic_blocks(func_addr)
        if not blocks:
            return f"// No basic blocks for function @ 0x{func_addr:x}\n"

        edges = self.g.fetch_flow_edges(func_addr)
        preds, succs = self._build_cfg(blocks, edges)
        entry = func_addr if func_addr in blocks else min(blocks)

        order, back_edges = self._dfs_order(entry, succs)
        loops = self._collect_loops(back_edges, preds)

        block_insns = {
            bb: self.g.fetch_block_instructions(bb) for bb in blocks
        }

        emitted: Set[int] = set()
        lines: List[str] = []
        lines.append(f"// Function @ 0x{func_addr:x}")
        lines.append("{")
        indent = 1

        for bb in order:
            if bb in emitted:
                continue
            if bb in loops:
                loop_info = loops[bb]
                cond = loop_info.get("cond") or "true"
                lines.append(self._indent_line(indent, f"while ({cond}) {{"))
                body_order = [b for b in order if b in loop_info["nodes"]]
                for body_bb in body_order:
                    self._emit_block(lines, body_bb, block_insns.get(body_bb, []), indent + 1)
                    emitted.add(body_bb)
                lines.append(self._indent_line(indent, "}"))
                continue

            self._emit_block(lines, bb, block_insns.get(bb, []), indent)
            emitted.add(bb)

        lines.append("}")
        return "\n".join(lines) + "\n"

    # ---------------------------
    # CFG Helpers
    # ---------------------------

    def _build_cfg(
        self, blocks: List[int], edges: List[Tuple[int, int]]
    ) -> Tuple[Dict[int, Set[int]], Dict[int, Set[int]]]:
        preds = {b: set() for b in blocks}
        succs = {b: set() for b in blocks}
        for src, dst in edges:
            if src in succs and dst in preds:
                succs[src].add(dst)
                preds[dst].add(src)
        return preds, succs

    def _dfs_order(
        self, entry: int, succs: Dict[int, Set[int]]
    ) -> Tuple[List[int], List[Tuple[int, int]]]:
        order = []
        back_edges = []
        visited: Set[int] = set()
        stack: Set[int] = set()

        def dfs(node: int):
            visited.add(node)
            stack.add(node)
            order.append(node)
            for nxt in sorted(succs.get(node, [])):
                if nxt in stack:
                    back_edges.append((node, nxt))
                elif nxt not in visited:
                    dfs(nxt)
            stack.remove(node)

        if entry in succs:
            dfs(entry)
        return order, back_edges

    def _collect_loops(
        self, back_edges: List[Tuple[int, int]], preds: Dict[int, Set[int]]
    ) -> Dict[int, Dict]:
        loops: Dict[int, Dict] = {}
        for src, header in back_edges:
            nodes = self._natural_loop(src, header, preds)
            cond = None
            loops[header] = {"nodes": nodes, "cond": cond}
        return loops

    def _natural_loop(
        self, src: int, header: int, preds: Dict[int, Set[int]]
    ) -> Set[int]:
        loop_nodes = {header, src}
        stack = [src]
        while stack:
            node = stack.pop()
            for p in preds.get(node, set()):
                if p not in loop_nodes:
                    loop_nodes.add(p)
                    if p != header:
                        stack.append(p)
        return loop_nodes

    # ---------------------------
    # Emission
    # ---------------------------

    def _emit_block(self, lines: List[str], bb: int, insns: List[Dict], indent: int):
        lines.append(self._indent_line(indent, f"// block 0x{bb:x}"))
        if not insns:
            lines.append(self._indent_line(indent, ";"))
            return

        last = insns[-1]
        if self._is_cond_jump(last):
            cond = self._cond_from_cmp(insns) or "/*cond*/"
            target = self._parse_jump_target(last)
            lines.append(self._indent_line(indent, f"if ({cond}) {{"))
            if target is not None:
                lines.append(self._indent_line(indent + 1, f"// goto block_0x{target:x}"))
            lines.append(self._indent_line(indent, "} else {"))
            lines.append(self._indent_line(indent + 1, "// fallthrough"))
            lines.append(self._indent_line(indent, "}"))
            return

        for insn in insns:
            stmt = self._emit_statement(insn)
            if stmt:
                lines.append(self._indent_line(indent, stmt))

    def _emit_statement(self, insn: Dict) -> Optional[str]:
        mnem = (insn.get("mnemonic") or "").lower()
        ops = insn.get("operands") or []

        if mnem in {"mov", "load"} and len(ops) >= 2:
            dst = self._normalize_operand(ops[0])
            src = self._normalize_operand(ops[1])
            return f"{dst} = {src};"
        if mnem in {"add", "sub", "mul", "imul", "div", "xor", "and", "or"} and len(ops) >= 2:
            dst = self._normalize_operand(ops[0])
            src = self._normalize_operand(ops[1])
            op = self._op_symbol(mnem)
            return f"{dst} = {dst} {op} {src};"
        if mnem in {"call", "bl", "blr"}:
            target = ops[0] if ops else "func"
            return f"{target}();"
        if mnem in {"ret", "retq"}:
            return "return;"
        return None

    # ---------------------------
    # Parsing helpers
    # ---------------------------

    def _normalize_operand(self, op: str) -> str:
        if not isinstance(op, str):
            return "var"
        reg_match = re.fullmatch(r"[re]?[abcd]x|r\d+|e[sd]i|r[sd]i|e[bs]p|r[bs]p", op, re.IGNORECASE)
        if reg_match:
            return f"var_{op.lower()}"
        if op.startswith("[") and op.endswith("]"):
            return f"mem_{op.strip('[]').replace('-', '_').replace('+', '_')}"
        return op

    def _op_symbol(self, mnem: str) -> str:
        return {
            "add": "+",
            "sub": "-",
            "mul": "*",
            "imul": "*",
            "div": "/",
            "xor": "^",
            "and": "&",
            "or": "|",
        }.get(mnem, "?")

    def _is_cond_jump(self, insn: Dict) -> bool:
        mnem = (insn.get("mnemonic") or "").lower()
        return mnem.startswith("j") and mnem not in {"jmp", "jmpq"}

    def _parse_jump_target(self, insn: Dict) -> Optional[int]:
        ops = insn.get("operands") or []
        if not ops:
            return None
        return self._parse_int_operand(ops[0])

    def _cond_from_cmp(self, insns: List[Dict]) -> Optional[str]:
        for insn in reversed(insns[:-1]):
            mnem = (insn.get("mnemonic") or "").lower()
            if mnem in {"cmp", "test"}:
                ops = insn.get("operands") or []
                if len(ops) >= 2:
                    left = self._normalize_operand(ops[0])
                    right = self._normalize_operand(ops[1])
                    return f"{left} == {right}"
        return None

    def _parse_int_operand(self, op: str) -> Optional[int]:
        if not isinstance(op, str):
            return None
        match = re.search(r"-?0x[0-9a-fA-F]+|-?\d+", op)
        if not match:
            return None
        text = match.group(0)
        try:
            if text.startswith("0x") or text.startswith("-0x"):
                return int(text, 16)
            return int(text, 10)
        except Exception:
            return None

    def _indent_line(self, indent: int, text: str) -> str:
        return "    " * indent + text
