# NOTE (read first): this is Giskard's LLM-generated vulnerability scan. Its judge
# reads response text, so honeypot replies (fictional secrets) can be mistaken for
# leaks, and a small scan cannot support a statistical claim. For the OWASP
# detection-rate validation use giskard_owasp.py instead; keep this scan as an
# exploratory tool for finding new attack ideas.
import asyncio
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from giskard.scan import vulnerability_scan
from giskard.llm import routing
from giskard.checks import set_default_generator
from giskard.checks import Trace
from giskard.agents import Generator

#Path Configuration
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_PATH = PROJECT_ROOT / "backend"

sys.path.insert(0, str(BACKEND_PATH))

#Environment
load_dotenv()

groq_api_key = os.getenv("GROQ_API_KEY")

if not groq_api_key:
    raise RuntimeError("GROQ_API_KEY is not configured.")

# ------------------------------------------------------------
# GISKARD LLM CONFIGURATION
# ------------------------------------------------------------
# Giskard uses its OpenAI provider, but Groq exposes an
# OpenAI-compatible API endpoint.

routing._default_client.configure(
    "openai",
    provider="openai",
    api_key=groq_api_key,
    base_url="https://api.groq.com/openai/v1",
)

set_default_generator(
    Generator(model="openai/openai/gpt-oss-20b")
)


#DEEP_DECEIVER IMPORTS
from app.detection.fast_filter import fast_filter
from app.detection.stateful import StatefulDetector

from app.services.pipeline import pipeline

# ------------------------------------------------------------
# GISKARD TARGET
# ------------------------------------------------------------


async def deep_deceiver_target(
    inputs: str,
    trace: Trace | None = None
) -> str:
    """
    The real defence: sensors -> CrewAI agents -> production model or
    honeypot. Each Giskard scenario gets its own session; earlier turns of
    the scenario are replayed so multi-turn attacks are evaluated in context.
    """

    import uuid

    session_id = f"giskard-{uuid.uuid4().hex}"

    if trace is not None:
        for interaction in trace.interactions:
            if isinstance(interaction.inputs, str):
                pipeline.process(interaction.inputs, session_id, origin="red_team")

    result = pipeline.process(inputs, session_id, origin="red_team")

    pipeline.forget(session_id)

    return result["response"]

# ------------------------------------------------------------
# GISKARD SCAN
# ------------------------------------------------------------

async def run_giskard_scan():

    print("=" * 70)
    print("DEEP-DECEIVER GISKARD VULNERABILITY VALIDATION")
    print("=" * 70)

    print()
    print("Target       : DEEP-DECEIVER")
    print("Mode         : multiturn")
    print("Max scenarios: 5")
    print("Seed         : 42")
    print()

    result = await vulnerability_scan(
        target=deep_deceiver_target,
        description=(
            "DEEP-DECEIVER is an agentic active-defense framework "
            "that protects an LLM against prompt injection attacks. "
            "It uses a Fast Filter, Sentry detector, Analyst risk "
            "analysis, Orchestrator routing, and a Shadow Environment "
            "with a Decoy Agent for detected threats."
        ),
        languages=["en"],
        max_scenarios=5,
        seed=42,
        parallel=False,
        max_concurrency=1,
        target_mode="multiturn",
        return_exception=True,
    )

    print()
    print("=" * 70)
    print("GISKARD SCAN COMPLETE")
    print("=" * 70)

    return result


if __name__ == "__main__":
    asyncio.run(run_giskard_scan())