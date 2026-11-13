"""Custom tools for Neural Shields (agents that detect and mitigate cyber threats).

Seam under test: the typed tool contract AND side-effect-aware dispatch. A
threat-response agent has two very different kinds of action - LOOKING at
telemetry (safe, parallelizable, cacheable) and CHANGING the system to contain a
threat (must be sequenced, never cached). fairlib encodes that difference in one
declared attribute per tool: side_effect. Getting this taxonomy to fit a real
detect-then-mitigate loop is exactly what this capstone probes.

You implement these by subclassing AbstractTool from the outside - never by
editing fairlib. The example below is a READ_ONLY detector; a MUTATING responder
is sketched underneath. Replace both with your real effectors.
"""

from pydantic import BaseModel
from fairlib import ToolRegistry, SafeCalculatorTool
from fairlib.core.errors import ToolInvocationError
from fairlib.core.interfaces.tools import (
    AbstractTool,
    SideEffect,
    StringInput,
    ToolOutput,
)

class ThreatVerdict(ToolOutput):
    """Structured result of scanning one line of telemetry."""
    suspicious: bool
    reason: str

    def render(self) -> str:
        flag = "SUSPICIOUS" if self.suspicious else "clean"
        return f"{flag}: {self.reason}"


class LogLineScannerTool(AbstractTool):
    """Classify a single log line as suspicious or clean.

    READ_ONLY: it only inspects its input. That declaration is what lets the
    framework run detectors in parallel and cache them - the privileged class.
    Swap the toy keyword check for your real detection logic / model call.
    """

    name = "scan_log_line"
    description = (
        "Inspect one line of system or network telemetry and decide whether it "
        "looks like a cyber threat. Input is the raw log line."
    )
    input_schema = StringInput
    output_schema = ThreatVerdict
    side_effect = SideEffect.READ_ONLY

    _MARKERS = ("failed password", "sqlmap", "/etc/shadow", "powershell -enc")

    async def acall(self, tool_input: StringInput) -> ThreatVerdict:
        try:
            line = tool_input.input.lower()
        except Exception as exc:  # noqa: BLE001 - re-raised as the typed tool error
            raise ToolInvocationError(
                f"could not scan log line: {exc}", tool_name=self.name
            ) from exc
        hit = next((m for m in self._MARKERS if m in line), None)
        if hit:
            return ThreatVerdict(suspicious=True, reason=f"matched indicator '{hit}'")
        return ThreatVerdict(suspicious=False, reason="no known indicators")


# The mitigation half of the loop is where side_effect earns its keep. A tool
# that quarantines a host CHANGES the world, so it declares MUTATING - the
# framework then refuses to run it in parallel or cache it. Sketch:
#
#   class QuarantineInput(BaseModel):
#       host_id: str
#
#   class QuarantineTool(AbstractTool):
#       name = "quarantine_host"
#       description = "Isolate a host from the network to contain a threat."
#       input_schema = QuarantineInput
#       output_schema = TextResult
#       side_effect = SideEffect.MUTATING     # never parallel, never cached
#       async def acall(self, tool_input: QuarantineInput) -> TextResult:
#           ...
#
# FINDING to watch for: if the READ_ONLY / MUTATING / EXTERNAL taxonomy cannot
# cleanly classify a real action your capstone needs (e.g. a "dry-run" mitigation
# that mutates a sandbox but not production), report it to the FAIR Lab team -
# that is the seam talking.

def build_tool_registry() -> ToolRegistry:
    tools = ToolRegistry()
    tools.register_tool(SafeCalculatorTool())
    return tools
