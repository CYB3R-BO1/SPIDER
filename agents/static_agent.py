import r2pipe
from core.capabilities import Capability
from storage.graph_store import GraphStore
from bus.event_bus import EventBus

class StaticAgent:
    """
    Performs initial static analysis using radare2.
    Extracts:
    - Functions
    - Basic blocks
    - Instructions
    - CFG flow edges
    Populates the graph DB.
    """
    CAPABILITIES = {Capability.STATIC_READ, Capability.STATIC_WRITE}

    def __init__(self, graph_store: GraphStore, bus: EventBus):
        self.g = graph_store
        self.bus = bus

    def run(self, binary_path: str):
        def safe_cmdj(r2, command: str):
            try:
                return r2.cmdj(command)
            except Exception:
                return None

        def parse_int(value, default=None):
            try:
                return int(value)
            except Exception:
                return default

        def extract_blocks(agfbj_data):
            if isinstance(agfbj_data, dict):
                if isinstance(agfbj_data.get("blocks"), list):
                    return agfbj_data["blocks"]
                return []
            if isinstance(agfbj_data, list):
                return agfbj_data
            return []

        r2 = None
        function_count = 0
        try:
            r2 = r2pipe.open(binary_path)
            r2.cmd("aaa")

            functions = safe_cmdj(r2, "aflj")
            if not isinstance(functions, list):
                functions = []

            for func in functions:
                if not isinstance(func, dict):
                    continue

                func_addr = parse_int(func.get("offset"))
                func_name = func.get("name") or f"sub_{func_addr:x}" if func_addr is not None else None
                if func_addr is None or func_name is None:
                    continue

                self.g.create_function(func_name, func_addr)
                function_count += 1

                agfbj = safe_cmdj(r2, f"agfbj {func_addr}")
                blocks = extract_blocks(agfbj)

                block_addrs = []
                for block in blocks:
                    if not isinstance(block, dict):
                        continue
                    bb_addr = parse_int(block.get("addr"))
                    if bb_addr is None:
                        continue
                    block_addrs.append(bb_addr)
                    self.g.create_basic_block(func_addr, bb_addr)

                # Add flow edges
                for block in blocks:
                    if not isinstance(block, dict):
                        continue
                    src_addr = parse_int(block.get("addr"))
                    if src_addr is None:
                        continue

                    dsts = []
                    if isinstance(block.get("edges"), list):
                        for edge in block["edges"]:
                            if isinstance(edge, dict):
                                dsts.append(parse_int(edge.get("to")))
                            else:
                                dsts.append(parse_int(edge))
                    else:
                        dsts.append(parse_int(block.get("jump")))
                        dsts.append(parse_int(block.get("fail")))

                    for dst in dsts:
                        if dst is None or dst not in block_addrs:
                            continue
                        self.g.add_flow_edge(src_addr, dst)

                # Instructions per block
                for block in blocks:
                    if not isinstance(block, dict):
                        continue
                    bb_addr = parse_int(block.get("addr"))
                    bb_size = parse_int(block.get("size"), 0)
                    if bb_addr is None or bb_size is None or bb_size <= 0:
                        continue

                    insns = safe_cmdj(r2, f"pdj {bb_size} @ {bb_addr}")
                    if not isinstance(insns, list):
                        continue

                    for insn in insns:
                        if not isinstance(insn, dict):
                            continue
                        insn_addr = parse_int(insn.get("offset"))
                        mnemonic = insn.get("mnemonic")
                        if not mnemonic:
                            opcode = insn.get("opcode")
                            if isinstance(opcode, str) and opcode.strip():
                                mnemonic = opcode.strip().split()[0]
                        operands = []
                        op_str = insn.get("op_str")
                        if isinstance(op_str, str) and op_str.strip():
                            operands = [o.strip() for o in op_str.split(",") if o.strip()]

                        if insn_addr is None or not mnemonic:
                            continue
                        self.g.create_instruction(bb_addr, insn_addr, mnemonic, operands)

        finally:
            if r2 is not None:
                try:
                    r2.quit()
                except Exception:
                    pass

        self.bus.publish("STATIC_ANALYSIS_COMPLETE", {"function_count": function_count})
