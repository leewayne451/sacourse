"""LLM backends. One generic OpenAI-compatible client covers most options:

  Ollama (local, free)   base_url=http://localhost:11434/v1   model=qwen2.5:14b (or llama3.1:8b ...)
  LM Studio / vLLM       base_url=http://localhost:1234/v1 (or your server)
  OpenAI / Groq / etc.   base_url from the provider, key in TRIAGE_LLM_API_KEY

Configure with flags or env vars TRIAGE_LLM_BASE_URL, TRIAGE_LLM_MODEL, TRIAGE_LLM_API_KEY.
"""
from __future__ import annotations

import json
import os
import urllib.request


class OpenAICompatLLM:
    def __init__(self, model: str | None = None, base_url: str | None = None, api_key: str | None = None,
                 temperature: float = 0.0, timeout: int = 600, json_mode: bool = True):
        self.model = model or os.environ.get("TRIAGE_LLM_MODEL", "qwen2.5:14b")
        self.base_url = (base_url or os.environ.get("TRIAGE_LLM_BASE_URL", "http://localhost:11434/v1")).rstrip("/")
        self.api_key = api_key or os.environ.get("TRIAGE_LLM_API_KEY", "not-needed")
        self.temperature = temperature
        self.timeout = timeout
        self.json_mode = json_mode

    def chat(self, messages: list[dict]) -> str:
        body = {"model": self.model, "messages": messages, "temperature": self.temperature}
        if self.json_mode:
            body["response_format"] = {"type": "json_object"}
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read())
        return data["choices"][0]["message"]["content"]

    def describe(self) -> str:
        return f"{self.model} @ {self.base_url}"
