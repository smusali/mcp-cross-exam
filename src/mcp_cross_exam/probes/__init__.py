from mcp_cross_exam.probes.base import (
    Observation,
    Probe,
    ProbeContext,
    ToolView,
    is_empty_success,
    tool_class,
)

__all__ = [
    "ALL_PROBES",
    "Observation",
    "Probe",
    "ProbeContext",
    "ToolView",
    "all_probes",
    "is_empty_success",
    "tool_class",
]


def all_probes() -> tuple[Probe, ...]:
    from mcp_cross_exam.findings import IMPACTS
    from mcp_cross_exam.probes.schema import probes as schema_probes
    from mcp_cross_exam.probes.transport import probes as transport_probes

    transport_probes()
    found = schema_probes()
    for probe in found:
        text = IMPACTS.get(probe.id, "")
        kind = type(probe)
        if text and not kind.impact:
            kind.impact = text
            kind.summary = text
    return found


ALL_PROBES: tuple[Probe, ...] = all_probes()
