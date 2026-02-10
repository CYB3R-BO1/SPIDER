"""
Defines capability permissions for each agent.
Purpose:
- Prevent unauthorized operations.
- Maintain safe, deterministic multi-agent behavior.
"""

class Capability:
    READ_GRAPH = "read_graph"
    WRITE_GRAPH = "write_graph"
    EXECUTE_BINARY = "execute_binary"
    GENERATE_SEMANTICS = "generate_semantics"
    VERIFY_FACTS = "verify_facts"
