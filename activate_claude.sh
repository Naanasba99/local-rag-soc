#!/usr/bin/env bash
# activate_claude.sh — Active le mode Claude API pour SOC FEED ELITE
# Usage : source ./activate_claude.sh

ENV_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.env"

if [ ! -f "$ENV_FILE" ]; then
    echo "❌ Fichier .env introuvable : $ENV_FILE"
    return 1
fi

export ANTHROPIC_API_KEY=$(grep ANTHROPIC_API_KEY "$ENV_FILE" | cut -d'=' -f2-)
export LLM_PROVIDER=claude

if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "❌ ANTHROPIC_API_KEY vide dans .env"
    return 1
fi

echo "✅ Mode Claude API activé"
echo "   Clé  : ${ANTHROPIC_API_KEY:0:12}************"
echo "   Mode : $LLM_PROVIDER"
echo ""
echo "   Usage   : python3 soc_ask_v2.py --mode [blue|red|hunt|extract] --question '...'"
echo "   Retour  : source deactivate_claude.sh"
