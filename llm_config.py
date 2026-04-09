#!/usr/bin/env python3
"""
LLM Config — Switch local/Claude API
  Mode local (défaut) :
    python3 soc_ask_v2.py ...

  Mode Claude API :
    export LLM_PROVIDER=claude
    export ANTHROPIC_API_KEY=sk-ant-xxxxx
    python3 soc_ask_v2.py ...

  Retour local :
    unset LLM_PROVIDER
"""

import os

LLM_PROVIDER     = os.getenv("LLM_PROVIDER", "local")
LLM_MODEL_LOCAL  = "mistral"
LLM_MODEL_CLAUDE = "claude-haiku-4-5-20251001"

def get_llm():
    if LLM_PROVIDER == "claude":
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(
                "❌ ANTHROPIC_API_KEY non définie.\n"
                "   Lance : export ANTHROPIC_API_KEY=sk-ant-xxxxx"
            )
        from langchain_anthropic import ChatAnthropic
        print(f"🤖 LLM : Claude API ({LLM_MODEL_CLAUDE})")
        return ChatAnthropic(
            model=LLM_MODEL_CLAUDE,
            api_key=api_key,
            max_tokens=2048
        )
    else:
        from langchain_ollama import OllamaLLM
        print(f"🤖 LLM : Ollama local ({LLM_MODEL_LOCAL})")
        return OllamaLLM(model=LLM_MODEL_LOCAL)
