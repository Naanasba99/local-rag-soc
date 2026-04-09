#!/usr/bin/env bash
# deactivate_claude.sh — Retour au mode local Mistral
unset LLM_PROVIDER
unset ANTHROPIC_API_KEY
echo "✅ Mode local Mistral activé"
