import re
from typing import Dict, List, Optional, Set, Tuple

from storage.graph_store import GraphStore
from bus.event_bus import EventBus


class SemanticAgent:
    """
    Generates human-level understanding using LLMs.
    Responsibilities:
    - Read normalized CFG, IR, and dataflow.
    - Produce multi-level explanations of function logic.
    - Detect high-level intent of code.
    - Identify potential vulnerabilities.
    - Output summaries that humans can understand.
    """

    def __init__(self, graph_store: GraphStore, bus: Optional[EventBus] = None):
        self.g = graph_store
        self.bus = bus

    def explain_function(self, func_addr: int) -> Dict:
        func_name = self._lookup_function_name(func_addr)
        blocks = self.g.fetch_basic_blocks(func_addr)
        edges = self.g.fetch_flow_edges(func_addr)

        block_insns = {
            bb: self.g.fetch_block_instructions(bb) for bb in blocks
        }

        calls = self._collect_calls(block_insns)
        loops = self._detect_back_edges(blocks, edges)
        variables = self._extract_variables(block_insns)
        vulnerabilities = self._detect_vulnerabilities(block_insns, calls)

        steps = []
        if blocks:
            steps.append(
                f"Builds CFG with {len(blocks)} basic blocks and {len(edges)} edges."
            )
        if loops:
            steps.append(
                f"Contains {len(loops)} loop(s) based on back-edges to earlier blocks."
            )
        if calls:
            steps.append(f"Calls {len(calls)} external/internal target(s): {', '.join(calls)}.")
        if self._has_branching(block_insns):
            steps.append("Performs conditional branching based on comparisons or tests.")
        if self._has_memory_ops(block_insns):
            steps.append("Moves or manipulates memory through load/store-like instructions.")

        summary = self._build_summary(
            func_name=func_name,
            func_addr=func_addr,
            blocks=len(blocks),
            edges=len(edges),
            loops=len(loops),
            calls=calls,
        )

        result = {
            "summary": summary,
            "steps": steps,
            "variables": variables,
            "vulnerabilities": vulnerabilities,
        }

        if self.bus is not None:
            self.bus.publish(
                "SEMANTIC_EXPLANATION_READY",
                {"func_addr": func_addr, "summary": summary},
            )

        return result

    # ---------------------------
    # Data extraction
    # ---------------------------

    def _lookup_function_name(self, func_addr: int) -> str:
        for func in self.g.fetch_functions():
            if func.get("addr") == func_addr:
                return func.get("name") or f"sub_{func_addr:x}"
        return f"sub_{func_addr:x}"

    def _collect_calls(self, block_insns: Dict[int, List[Dict]]) -> List[str]:
        targets: Set[str] = set()
        for insns in block_insns.values():
            for insn in insns:
                mnem = (insn.get("mnemonic") or "").lower()
                if mnem in {"call", "bl", "blr"}:
                    ops = insn.get("operands") or []
                    if ops:
                        targets.add(ops[0])
        return sorted(targets)

    def _detect_back_edges(
        self, blocks: List[int], edges: List[Tuple[int, int]]
    ) -> List[Tuple[int, int]]:
        block_set = set(blocks)
        back_edges = []
        for src, dst in edges:
            if src in block_set and dst in block_set and dst <= src:
                back_edges.append((src, dst))
        return back_edges

    def _extract_variables(self, block_insns: Dict[int, List[Dict]]) -> List[Dict]:
        regs = set()
        stack_vars = set()
        immediates = set()

        reg_pattern = re.compile(r"\b(r[abcd]x|r[bs]p|r[sd]i|r\d+|e[abcd]x|e[bs]p|e[sd]i)\b", re.IGNORECASE)
        stack_pattern = re.compile(r"\[(rbp|rsp|ebp|esp)[+-]0x[0-9a-fA-F]+\]")
        imm_pattern = re.compile(r"\b0x[0-9a-fA-F]+\b|\b\d+\b")

        for insns in block_insns.values():
            for insn in insns:
                for op in insn.get("operands") or []:
                    for r in reg_pattern.findall(op):
                        regs.add(r.lower())
                    for s in stack_pattern.findall(op):
                        stack_vars.add(op)
                    for imm in imm_pattern.findall(op):
                        immediates.add(imm)

        variables = []
        for r in sorted(regs):
            variables.append({"name": r, "type": "register"})
        for s in sorted(stack_vars):
            variables.append({"name": s, "type": "stack_slot"})
        for imm in sorted(immediates):
            variables.append({"name": imm, "type": "immediate"})
        return variables

    def _detect_vulnerabilities(
        self, block_insns: Dict[int, List[Dict]], calls: List[str]
    ) -> List[Dict]:
        vulns = []
        unsafe = {"strcpy", "strcat", "gets", "sprintf", "vsprintf"}
        for target in calls:
            name = target.lower()
            if any(u in name for u in unsafe):
                vulns.append(
                    {
                        "type": "unsafe_call",
                        "detail": f"Call to {target} may be unsafe without bounds checks.",
                    }
                )

        if self._has_stack_alloc(block_insns) and not self._has_stack_checks(block_insns):
            vulns.append(
                {
                    "type": "stack_allocation",
                    "detail": "Stack allocation detected without obvious bounds checks.",
                }
            )

        return vulns

    # ---------------------------
    # Heuristic helpers
    # ---------------------------

    def _has_branching(self, block_insns: Dict[int, List[Dict]]) -> bool:
        for insns in block_insns.values():
            for insn in insns:
                mnem = (insn.get("mnemonic") or "").lower()
                if mnem.startswith("j") and mnem != "jmp":
                    return True
        return False

    def _has_memory_ops(self, block_insns: Dict[int, List[Dict]]) -> bool:
        mem_mnems = {"mov", "movs", "stos", "lods"}
        for insns in block_insns.values():
            for insn in insns:
                mnem = (insn.get("mnemonic") or "").lower()
                if mnem in mem_mnems:
                    return True
        return False

    def _has_stack_alloc(self, block_insns: Dict[int, List[Dict]]) -> bool:
        for insns in block_insns.values():
            for insn in insns:
                mnem = (insn.get("mnemonic") or "").lower()
                ops = insn.get("operands") or []
                if mnem == "sub" and len(ops) >= 2 and ops[0].lower() in {"rsp", "esp"}:
                    return True
        return False

    def _has_stack_checks(self, block_insns: Dict[int, List[Dict]]) -> bool:
        for insns in block_insns.values():
            for insn in insns:
                mnem = (insn.get("mnemonic") or "").lower()
                if mnem in {"cmp", "test"}:
                    return True
        return False

    def _build_summary(
        self,
        func_name: str,
        func_addr: int,
        blocks: int,
        edges: int,
        loops: int,
        calls: List[str],
    ) -> str:
        call_part = "no obvious calls" if not calls else f"{len(calls)} call(s)"
        loop_part = "no detected loops" if loops == 0 else f"{loops} loop(s)"
        return (
            f"{func_name} @ 0x{func_addr:x} has {blocks} blocks / {edges} edges, "
            f"{loop_part}, and {call_part}. This summary is derived from CFG and instruction stream."
        )
