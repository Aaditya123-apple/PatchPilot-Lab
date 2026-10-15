"""Runtime configuration read from environment variables and an optional .env file."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

DEFAULT_BASE_URL = "https://api.tokenfactory.us-central1.nebius.com/v1/"
DEFAULT_MODEL = "nvidia/nemotron-3-super-120b-a12b"
DEFAULT_FALLBACKS = "nvidia/Nemotron-3-Ultra-550b-a55b"


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    api_key: str | None = None
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    fallback_models: tuple[str, ...] = ()
    timeout_s: float = 120.0
    max_retries: int = 3
    max_concurrency: int = 4
    github_token: str | None = None

    @property
    def offline(self) -> bool:
        return not self.api_key

    @property
    def model_chain(self) -> tuple[str, ...]:
        chain: list[str] = []
        for name in (self.model, *self.fallback_models):
            if name and name not in chain:
                chain.append(name)
        return tuple(chain)


def get_settings() -> Settings:
    load_dotenv(override=False)
    key = os.getenv("NEBIUS_API_KEY", "").strip() or None
    if key and key.lower().startswith(("your", "<")):
        key = None
    fallbacks = tuple(
        m.strip() for m in os.getenv("NEBIUS_FALLBACK_MODELS", DEFAULT_FALLBACKS).split(",") if m.strip()
    )
    return Settings(
        api_key=key,
        base_url=os.getenv("NEBIUS_BASE_URL", DEFAULT_BASE_URL).strip() or DEFAULT_BASE_URL,
        model=os.getenv("NVIDIA_MODEL_NAME", DEFAULT_MODEL).strip() or DEFAULT_MODEL,
        fallback_models=fallbacks,
        timeout_s=_float("NEBIUS_TIMEOUT_SECONDS", 120.0),
        max_retries=max(0, _int("NEBIUS_MAX_RETRIES", 3)),
        max_concurrency=max(1, _int("AGENTX_MAX_CONCURRENCY", 4)),
        github_token=os.getenv("GITHUB_TOKEN", "").strip() or None,
    )
