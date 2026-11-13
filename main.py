# Sprint 2 initial agent

"""PLUMBING"""
import os, asyncio, json
from dotenv import load_dotenv
from pathlib import Path
from pydantic import (
    BaseModel, 
    Field,
    ValidationError
)
from tools import build_tool_registry
from examples import EXAMPLES
from fairlib import (
    configure_settings,
    HuggingFaceAdapter,
    ToolExecutor,
    WorkingMemory,
    SimpleReActPlanner,
    SimpleAgent,
    RoleDefinition,
    FormatInstruction,
    Verdict,
    AgentEventBus
)

# Folder containing main.py and .env.
DEVELOPMENT_DIR = Path(__file__).resolve().parent
load_dotenv(DEVELOPMENT_DIR / ".env")

# DEFINE THE SCHEMA FOR A VALID JSON REPORT
class AnalysisReport(BaseModel):
    summary: str = Field(description="One or two sentences stating the conclusion.")
    findings: list[str] = Field(description="Specific pieces of evidence supporting the conclusion. Empty if no threat is established.")

"""CONFIGURE THE PROMPT
summary -> reaches through the planner instance to set the role, instructions, and example
returns -> None
"""
def configure_planner_prompt(planner: SimpleReActPlanner):
    builder = planner.prompt_builder

    # Role
    builder.role_definition = RoleDefinition(
        "You are a cybersecurity analyst. "
        "Analyze supplied evidence and do not invent threats."
    )

    # Format Instructions
    schema = json.dumps(AnalysisReport.model_json_schema(), indent=2)
    # Rule: evidence only (Req 3)
    builder.format_instructions.append(
        FormatInstruction(
            "Only report threats and vulnerabilities that are supported by evidence "
            "in the user's request or in tool results. If the evidence does not "
            "establish a threat, say so and leave findings empty."
        )
    )
    # Rule: tool input formats (keeps the two formats from colliding)
    builder.format_instructions.append(
        FormatInstruction(
            "For safe_calculator, tool_input is the bare arithmetic expression, "
            "such as 15 * 4, with no JSON and no field names. "
            "Use the calculator for any arithmetic instead of computing it yourself."
        )
    )
    # Output: the final report (Req 5)
    builder.format_instructions.append(
        FormatInstruction(
            "Use the required Thought and Action format. "
            "When finished, use tool_name: final_answer. "
            "Put a JSON report on the tool_input line, on a single line, "
            "with no markdown fences, matching this schema: "
            f"{schema}"
        )
    )

    # Examples. For testing, include an example for each tool.
    builder.examples.extend(EXAMPLES)

"""ASSEMBLE THE AGENT
summary -> includes the 5 parts of a working agent: model, planner, tool registry, executor, memory
returns -> SimpleAgent
"""
def build_agent():
    # loads optional framework settings
    settings_path = Path(DEVELOPMENT_DIR) / "settings.example.yml"
    if settings_path.exists():
        configure_settings(str(settings_path))
        
    # defines the model used by this agent
    model_name = os.getenv("FAIR_LLM_DEMO_MODEL", "Qwen/Qwen2.5-0.5B-Instruct")
    print(f"Loading {model_name} (first run downloads the weights)...")
    llm = HuggingFaceAdapter(model_name=model_name, max_new_tokens=512)
    print("Capabilities:", llm.get_model_capabilities())
    
    tools = build_tool_registry()
    executor = ToolExecutor(tools)
    memory = WorkingMemory()
    planner = SimpleReActPlanner(llm, tools)
    configure_planner_prompt(planner)
    print(planner.render_system_prompt())
    bus = AgentEventBus()

    # Assemble the pieces into a working agent.
    agent = SimpleAgent(
        llm=llm,
        planner=planner,
        tool_executor=executor,
        memory=memory,
        max_steps=10,
        events = bus
    )
    
    return agent  

"""SHOW AGENT MIND
summary -> steps through the agent's tool usage and reasoning at each step
returns -> None
"""
def show_agent_mind(agent: SimpleAgent, max_chars: int = 400):
    history = agent.memory.get_history()
    print("=" * 72)
    print(f"AGENT MIND - {len(history)} messages in working memory")
    print("=" * 72)
    for msg in history:
        text = msg.content if isinstance(msg.content, str) else str(msg.content)
        clipped = text[:max_chars]
        if len(text) > max_chars:
            clipped += f" ... [+{len(text) - max_chars} more chars]"
        print(f"--- {msg.role} " + "-" * (60 - len(msg.role)))
        print(clipped)
    print("=" * 72)
    print("END AGENT MIND")
    print("=" * 72)

"""CLEANS FINAL ANSWER
summary -> removes markdown fences if the model adds them so the JSON validator succeeds
returns -> Response str
"""
def clean_response(response: str):
    response = response.strip()
    if response.startswith("```json") and response.endswith("```"):
        return response[7:-3].strip()
    if response.startswith("```") and response.endswith("```"):
        return response[3:-3].strip()
    
    return response

"""VALIDATES FINAL ANSWER
summary -> ensures that the final answer fits the JSON AnalysisReport schema
returns -> Verdict
"""
async def validate_report(response: str) -> Verdict:
    cleaned = clean_response(response)

    try:
        AnalysisReport.model_validate_json(cleaned)
    except ValidationError as exc:
        return Verdict.reject(
            "Return only a JSON object through final_answer. "
            f"Fix these validation errors:\n{exc}"
        )

    return Verdict.approve()

"""RUNS THE AGENT
summary -> Run the agent and return a validated report
returns -> AnalysisReport
"""
async def run_request(agent: SimpleAgent, user_request: str) -> AnalysisReport:
    response = await agent.arun(
        user_request,
        validator=validate_report,
        max_retries=2,
    )

    return AnalysisReport.model_validate_json(
        clean_response(response)
    )
    
async def main():
    agent = build_agent()

    print("Agent ready. Type 'exit' to stop.")

    while True:
        user_request = input("\nYou: ").strip()

        if user_request.lower() in {"exit", "quit"}:
            break

        if not user_request:
            continue

        try:
            report = await run_request(agent, user_request)
        except Exception as exc:
            print(f"Request failed: {exc}")
            show_agent_mind(agent, max_chars=2000)
        else:
            print("\nValidated report:")
            print(report.model_dump_json(indent=2))
            show_agent_mind(agent, max_chars=2000)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopped.")
