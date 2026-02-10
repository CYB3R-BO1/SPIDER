"""
Defines system event types for inter-agent communication.
Purpose:
- Standardized event names for the event bus.
- Ensures agents interact without direct coupling.
"""

class Events:
    STATIC_ANALYSIS_COMPLETE = "static_complete"
    DYNAMIC_TRACE_READY = "dynamic_trace"
    SEMANTIC_SUMMARY_READY = "semantic_ready"
    VERIFY_REQUEST = "verify_request"
    VERIFY_RESULT = "verify_result"

