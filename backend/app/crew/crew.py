from crewai import Crew, Process

from app.crew.agents import (
    create_analyst_agent,
    create_orchestrator_agent,
    create_sentry_agent,
)
from app.crew.tasks import build_tasks


def build_security_crew(message: str, evidence: dict, recent_turns: list[str], llm=None) -> tuple[Crew, list]:
    """A fresh crew for one message: (Sentry || Analyst) -> Orchestrator."""

    agents = {
        "sentry": create_sentry_agent(llm),
        "analyst": create_analyst_agent(llm),
        "orchestrator": create_orchestrator_agent(llm),
    }

    tasks = build_tasks(agents, message, evidence, recent_turns)

    crew = Crew(
        name="DEEP-DECEIVER Security Analysis Crew",
        agents=list(agents.values()),
        tasks=tasks,
        process=Process.sequential,
        verbose=False,
        memory=False,
    )

    return crew, tasks
