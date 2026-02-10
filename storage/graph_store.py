import json
from neo4j import GraphDatabase
from typing import List, Dict


class GraphStore:
    """
    Wraps Neo4j graph DB operations.
    Creates and queries Function, BasicBlock, Instruction nodes.
    Manages FLOW, CALL, CONTAINS, and IN relationships.
    """

    def __init__(self, uri, user, password, database="ai-reverse-db"):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.database = database

    def session(self):
        return self.driver.session(database=self.database)
    
    def close(self):
        self.driver.close()

    # ---------------------------
    # Node Creation
    # ---------------------------

    def create_function(self, name: str, addr: int):
        query = """
        MERGE (f:Function {addr:$addr})
        SET f.name = $name
        RETURN f
        """
        with self.driver.session() as session:
            session.execute_write(lambda tx: tx.run(query, name=name, addr=addr))



    def create_basic_block(self, func_addr: int, bb_addr: int):
        query = """
        MATCH (f:Function {addr:$func_addr})
        MERGE (b:BasicBlock {addr:$bb_addr})
        MERGE (f)-[:CONTAINS]->(b)
        RETURN b
        """
        with self.driver.session() as session:
            session.execute_write(
                lambda tx: tx.run(query, func_addr=func_addr, bb_addr=bb_addr)
            )

    def create_instruction(self, bb_addr: int, addr: int, mnemonic: str, operands: List[str]):
        query = """
        MATCH (b:BasicBlock {addr:$bb_addr})
        MERGE (i:Instruction {addr:$addr})
        SET i.mnemonic = $mnemonic, i.operands = $operands
        MERGE (b)-[:IN]->(i)
        RETURN i
        """
        with self.driver.session() as session:
            session.execute_write(
                lambda tx: tx.run(
                    query,
                    bb_addr=bb_addr,
                    addr=addr,
                    mnemonic=mnemonic,
                    operands=operands,
                )
            )


    # ---------------------------
    # Relationships
    # ---------------------------

    def add_flow_edge(self, src_bb: int, dst_bb: int):
        query = """
        MATCH (a:BasicBlock {addr:$src}), (b:BasicBlock {addr:$dst})
        MERGE (a)-[:FLOW]->(b)
        """
        with self.driver.session() as session:
            session.execute_write(lambda tx: tx.run(query, src=src_bb, dst=dst_bb))

    def add_call_edge(self, src_func: int, dst_func: int):
        query = """
        MATCH (a:Function {addr:$src}), (b:Function {addr:$dst})
        MERGE (a)-[:CALL]->(b)
        """
        with self.driver.session() as session:
            session.execute_write(lambda tx: tx.run(query, src=src_func, dst=dst_func))

    # ---------------------------
    # Queries
    # ---------------------------

    def fetch_functions(self):
        query = """
        MATCH (f:Function)
        RETURN f.addr AS addr, f.name AS name
        ORDER BY f.addr
        """
        with self.driver.session() as session:
            return session.execute_read(
                lambda tx: [dict(r) for r in tx.run(query)]
            )

    def fetch_basic_blocks(self, func_addr: int):
        query = """
        MATCH (f:Function {addr:$func_addr})-[:CONTAINS]->(b:BasicBlock)
        RETURN b.addr AS addr
        ORDER BY b.addr
        """
        with self.driver.session() as session:
            return session.execute_read(
                lambda tx: [r["addr"] for r in tx.run(query, func_addr=func_addr)]
            )

    def fetch_all_basic_blocks(self):
        query = """
        MATCH (b:BasicBlock)
        RETURN b.addr AS addr
        ORDER BY b.addr
        """
        with self.driver.session() as session:
            return session.execute_read(
                lambda tx: [r["addr"] for r in tx.run(query)]
            )

    def fetch_flow_edges(self, func_addr: int):
        query = """
        MATCH (f:Function {addr:$func_addr})-[:CONTAINS]->(a:BasicBlock)-[:FLOW]->(b:BasicBlock)<-[:CONTAINS]-(f)
        RETURN a.addr AS src, b.addr AS dst
        ORDER BY a.addr, b.addr
        """
        with self.driver.session() as session:
            return session.execute_read(
                lambda tx: [(r["src"], r["dst"]) for r in tx.run(query, func_addr=func_addr)]
            )

    def fetch_all_flow_edges(self):
        query = """
        MATCH (a:BasicBlock)-[:FLOW]->(b:BasicBlock)
        RETURN a.addr AS src, b.addr AS dst
        ORDER BY a.addr, b.addr
        """
        with self.driver.session() as session:
            return session.execute_read(
                lambda tx: [(r["src"], r["dst"]) for r in tx.run(query)]
            )

    def fetch_flow_edges_from(self, src_bb: int):
        query = """
        MATCH (a:BasicBlock {addr:$src})-[:FLOW]->(b:BasicBlock)
        RETURN a.addr AS src, b.addr AS dst
        ORDER BY b.addr
        """
        with self.driver.session() as session:
            return session.execute_read(
                lambda tx: [(r["src"], r["dst"]) for r in tx.run(query, src=src_bb)]
            )

    def fetch_block_instructions(self, bb_addr: int):
        query = """
        MATCH (b:BasicBlock {addr:$bb_addr})-[:IN]->(i:Instruction)
        RETURN i.addr AS addr, i.mnemonic AS mnemonic, i.operands AS operands
        ORDER BY i.addr
        """
        with self.driver.session() as session:
            return session.execute_read(
                lambda tx: [dict(r) for r in tx.run(query, bb_addr=bb_addr)]
            )

    def mark_loop_header(
        self,
        bb_addr: int,
        loop_body=None,
        back_edges=None,
        loop_depth=None,
        crypto_constant_time=None,
    ):
        query = """
        MATCH (b:BasicBlock {addr:$bb_addr})
        SET b:LOOP,
            b.loop_header = true,
            b.loop_body = $loop_body,
            b.loop_back_edges = $loop_back_edges,
            b.loop_depth = $loop_depth,
            b.crypto_constant_time = $crypto_constant_time
        RETURN b
        """
        with self.driver.session() as session:
            session.execute_write(
                lambda tx: tx.run(
                    query,
                    bb_addr=bb_addr,
                    loop_body=loop_body,
                    loop_back_edges=back_edges,
                    loop_depth=loop_depth,
                    crypto_constant_time=crypto_constant_time,
                )
            )

    def set_function_properties(self, func_addr: int, props: Dict):
        query = """
        MATCH (f:Function {addr:$func_addr})
        SET f += $props
        RETURN f
        """
        with self.driver.session() as session:
            session.execute_write(
                lambda tx: tx.run(query, func_addr=func_addr, props=props)
            )

    def set_plugin_facts(self, func_addr: int, facts: Dict):
        query = """
        MATCH (f:Function {addr:$func_addr})
        SET f.plugin_facts = coalesce(f.plugin_facts, {}) + $facts
        RETURN f
        """
        with self.driver.session() as session:
            session.execute_write(
                lambda tx: tx.run(query, func_addr=func_addr, facts=facts)
            )

    def set_switch_info(self, func_addr: int, header_bb: int, cases: List[int]):
        query = """
        MATCH (f:Function {addr:$func_addr})-[:CONTAINS]->(b:BasicBlock {addr:$bb_addr})
        SET b:switch,
            b.switch_header = true,
            b.switch_cases = $cases
        RETURN b
        """
        with self.driver.session() as session:
            session.execute_write(
                lambda tx: tx.run(
                    query, func_addr=func_addr, bb_addr=header_bb, cases=cases
                )
            )

    def remove_flow_edge(self, src_bb: int, dst_bb: int):
        query = """
        MATCH (a:BasicBlock {addr:$src})-[r:FLOW]->(b:BasicBlock {addr:$dst})
        DELETE r
        """
        with self.driver.session() as session:
            session.execute_write(lambda tx: tx.run(query, src=src_bb, dst=dst_bb))

    def create_run(self, run_id: str, binary_path: str):
        query = """
        MERGE (r:Run {id:$run_id})
        SET r.binary_path = $binary_path
        RETURN r
        """
        with self.driver.session() as session:
            session.execute_write(
                lambda tx: tx.run(query, run_id=run_id, binary_path=binary_path)
            )

    def get_latest_run(self):
        query = """
        MATCH (r:Run)
        RETURN r.id AS id, r.binary_path AS binary_path
        ORDER BY r.id DESC
        LIMIT 1
        """
        with self.driver.session() as session:
            def _fn(tx):
                r = tx.run(query)
                row = r.single()
                if row:
                    return {"id": row.get("id"), "binary_path": row.get("binary_path")}
                return None

            return session.execute_read(_fn)

    # ---------------------------
    # Maintenance
    # ---------------------------

    def clear_graph(self):
        query = """
        MATCH (n)
        DETACH DELETE n
        """
        with self.driver.session() as session:
            session.execute_write(lambda tx: tx.run(query))

    def add_executes_edge(
        self,
        run_id: str,
        bb_addr: int,
        seq: int,
        pc: int,
        next_pc: int,
        regs: Dict,
    ):
        query = """
        MATCH (r:Run {id:$run_id}), (b:BasicBlock {addr:$bb_addr})
        CREATE (r)-[:EXECUTES {
            seq:$seq,
            pc:$pc,
            next_pc:$next_pc,
            regs:$regs
        }]->(b)
        """
        with self.driver.session() as session:
            session.execute_write(
                lambda tx: tx.run(
                    query,
                    run_id=run_id,
                    bb_addr=bb_addr,
                    seq=seq,
                    pc=pc,
                    next_pc=next_pc,
                    regs=regs,
                )
            )

    def add_runtime_flow(
        self,
        run_id: str,
        src_bb: int,
        dst_bb: int,
        seq: int,
        pc: int,
        next_pc: int,
        regs: Dict,
    ):
        query = """
        MATCH (r:Run {id:$run_id}),
              (a:BasicBlock {addr:$src}),
              (b:BasicBlock {addr:$dst})
        CREATE (a)-[:RUNTIME_FLOW {
            run_id:$run_id,
            seq:$seq,
            pc:$pc,
            next_pc:$next_pc,
            regs:$regs
        }]->(b)
        """
        with self.driver.session() as session:
            session.execute_write(
                lambda tx: tx.run(
                    query,
                    run_id=run_id,
                    src=src_bb,
                    dst=dst_bb,
                    seq=seq,
                    pc=pc,
                    next_pc=next_pc,
                    regs=regs,
                )
            )

    def add_syscall_event(
        self,
        run_id: str,
        seq: int,
        pc: int,
        syscall_number: int,
        args: List,
    ):
        query = """
        MATCH (r:Run {id:$run_id})
        CREATE (r)-[:SYSCALL_EVENT {
            seq:$seq,
            pc:$pc,
            syscall_number:$syscall_number,
            args:$args
        }]->(s:Syscall {number:$syscall_number})
        """
        with self.driver.session() as session:
            session.execute_write(
                lambda tx: tx.run(
                    query,
                    run_id=run_id,
                    seq=seq,
                    pc=pc,
                    syscall_number=syscall_number,
                    args=args,
                )
            )

    def fetch_runtime_flow_edges(self):
        query = """
        MATCH (a:BasicBlock)-[r:RUNTIME_FLOW]->(b:BasicBlock)
        RETURN a.addr AS src, b.addr AS dst
        ORDER BY a.addr, b.addr
        """
        with self.driver.session() as session:
            return session.execute_read(lambda tx: [(r["src"], r["dst"]) for r in tx.run(query)])

    def fetch_executed_blocks(self):
        query = """
        MATCH (r:Run)-[:EXECUTES]->(b:BasicBlock)
        RETURN DISTINCT b.addr AS addr
        ORDER BY b.addr
        """
        with self.driver.session() as session:
            return session.execute_read(lambda tx: [r["addr"] for r in tx.run(query)])

    def mark_flow_edge_suspect(self, src_bb: int, dst_bb: int):
        query = """
        MATCH (a:BasicBlock {addr:$src})-[r:FLOW]->(b:BasicBlock {addr:$dst})
        SET r.suspect = true
        RETURN r
        """
        with self.driver.session() as session:
            session.execute_write(lambda tx: tx.run(query, src=src_bb, dst=dst_bb))

    def set_verification_results(self, results: Dict):
        query = """
        MERGE (v:VerificationSummary {id:"latest"})
        SET v.data = $data
        RETURN v
        """
        with self.driver.session() as session:
            # Neo4j properties must be primitives or arrays; store complex
            # verification blobs as JSON strings to avoid type errors.
            session.execute_write(lambda tx: tx.run(query, data=json.dumps(results)))

    def get_verification_results(self):
        query = """
        MATCH (v:VerificationSummary {id:"latest"})
        RETURN v.data AS data
        """
        with self.driver.session() as session:
            def _fn(tx):
                r = tx.run(query)
                row = r.single()
                if row:
                    data = row.get("data")
                    try:
                        return json.loads(data)
                    except Exception:
                        return data
                return None

            return session.execute_read(_fn)

    def set_semantic_summaries(self, summaries: Dict):
        query = """
        MERGE (s:SemanticSummary {id:"latest"})
        SET s.data = $data
        RETURN s
        """
        with self.driver.session() as session:
            session.execute_write(lambda tx: tx.run(query, data=json.dumps(summaries)))

    def get_semantic_summaries(self):
        query = """
        MATCH (s:SemanticSummary {id:"latest"})
        RETURN s.data AS data
        """
        with self.driver.session() as session:
            def _fn(tx):
                r = tx.run(query)
                row = r.single()
                if row:
                    data = row.get("data")
                    try:
                        return json.loads(data)
                    except Exception:
                        return data
                return None

            return session.execute_read(_fn)
