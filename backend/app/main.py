import os

# CrewAI/OpenTelemetry telemetry stays off: security prompts never leave this host.
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.security.alerts import alert_engine

from fastapi.middleware.cors import CORSMiddleware

from app.api.chat import router as chat_router
from app.api.benchmark import router as benchmark_router
from app.api.ops import router as ops_router
from app.api.soc import router as soc_router
from app.api.security import router as security_router
from app.api.red_team import router as red_team_router

@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Warm the local detectors in the background so the first real message
    # does not pay the model-loading cost.
    def warm_up():
        try:
            from app.services.pipeline import pipeline

            pipeline.warm_up()
        except Exception:
            pass

    threading.Thread(target=warm_up, daemon=True).start()

    yield

    # Let open Server-Sent-Event streams finish so shutdown / reload
    # is not blocked by connected dashboards.
    alert_engine.broadcaster.close()


app = FastAPI(
    title="DEEP-DECEIVER",
    description="Agentic Active-Defense Framework for securing LLMs against Prompt Injection",
    version="0.1.0",
    lifespan=lifespan,
)

# Allow requests from the React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173",
        ).split(",")
        if origin.strip()
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(chat_router)
app.include_router(soc_router)
app.include_router(benchmark_router)
app.include_router(ops_router)
app.include_router(security_router)
app.include_router(red_team_router)

@app.get("/")
def root():
    return {
        "message": "DEEP-DECEIVER backend is running",
        "status": "online"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }
