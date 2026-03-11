# 🧠 LOCAL RAG SOC — Assistant IA Offline pour Analystes Cyber

> *"La dépendance au cloud est une vulnérabilité. L'autonomie est une compétence."*

## 🎯 C'est quoi ?

Un système RAG (Retrieval-Augmented Generation) **100% local et offline** conçu pour les analystes SOC, DFIR et Threat Hunters.

Tu poses une question en langage naturel → le système cherche dans ta base de connaissance personnelle → un LLM local génère une réponse sourcée.

**Zéro cloud. Zéro abonnement. Zéro fuite de données.**

---

## ⚡ Pourquoi c'est différent

| Approche classique | Ce système |
|---|---|
| Google + 10 onglets | Une question → une réponse sourcée |
| ChatGPT (cloud, logs) | LLM local, données privées |
| Abonnement 50 000$/an | Gratuit, open-source |
| Inutilisable hors ligne | Fonctionne sans internet |
| Connaissance générique | Ta bibliothèque personnelle |

---

## 🏗️ Architecture
```
Question (langage naturel)
        ↓
   ChromaDB (recherche vectorielle)
        ↓
   ~400 000 chunks indexés
        ↓
   nomic-embed-text (embeddings)
        ↓
   qwen2.5:7b (LLM local via Ollama)
        ↓
Réponse sourcée + fichiers cités
```

---

## 📚 Sources indexées

- **MITRE ATT&CK** — 704 techniques complètes
- **SigmaHQ** — 3000+ règles de détection
- **Atomic Red Team** — Tests MITRE mappés
- **MITRE CAR** — Analytics officiels
- **Mordor Datasets** — Logs d'attaques réelles
- **Hayabusa** — Threat hunting Windows
- **CISA KEV** — 253 advisories officiels
- **Livres techniques** — Linux, DFIR, Threat Hunting
- **Notes personnelles** — Playbooks, scénarios, exercises

---

## 🚀 Usage
```bash
# Poser une question
python3 soc_ask.py "Explique MITRE T1055 Process Injection"

# Mode interactif
python3 soc_ask.py --interactive

# Statistiques de la base
python3 soc_ask.py --stats

# Rebuild de la base
caffeinate -i python3 soc_ask.py --rebuild
```

---

## 🛠️ Stack technique

- **LLM** : qwen2.5:7b via [Ollama](https://ollama.com)
- **Embeddings** : nomic-embed-text
- **VectorDB** : ChromaDB
- **Orchestration** : LangChain
- **Language** : Python 3.14

---

## 📖 Documentation

- [Installation](docs/INSTALLATION.md)
- [Architecture détaillée](docs/ARCHITECTURE.md)
- [Sources et datasets](docs/SOURCES.md)

---

## 👤 Auteur

**Naanasba** — Transition Finance → Cybersécurité  
Parcours : SOC Analyst → DFIR → Threat Hunter  
GitHub : [@Naanasba99](https://github.com/Naanasba99)

---

## 🌍 Pourquoi en français ?

La communauté cyber francophone manque de ressources techniques de qualité.  
Ce projet est une contribution à cet écosystème.

---

*Construit pièce par pièce. Compris avant d'être utilisé.*
