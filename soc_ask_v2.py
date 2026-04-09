#!/usr/bin/env python3
"""
SOC RAG ELITE V2 — Assistant SOC/DFIR/Red/Blue Team local
Usage :
  python3 ~/soc_ask_v2.py --rebuild
  python3 ~/soc_ask_v2.py --mode blue --question "comment détecter un pass-the-hash"
  python3 ~/soc_ask_v2.py --mode red  --question "techniques de pivoting Windows"
  python3 ~/soc_ask_v2.py --mode extract --question "règles Sigma pour Kerberoasting"
  python3 ~/soc_ask_v2.py  (menu interactif)
"""

import os
import re
import argparse
from tqdm import tqdm
import chromadb
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_ollama import OllamaEmbeddings, OllamaLLM

# ===================== CONFIG =====================
SOC_BRAIN_PATH = os.path.expanduser("~/soc-brain")
DB_PATH        = os.path.expanduser("~/CYBER/soc-stack/soc-chroma-db-v2")
os.makedirs(DB_PATH, exist_ok=True)

BATCH_SIZE = 200   # chunks par batch d'insertion

# Modèles Ollama — change ici si tu veux utiliser autre chose
EMBED_MODEL = "nomic-embed-text"
LLM_MODEL   = "mistral"   # alternatives : mistral, llama3.2, deepseek-r1:7b

# Mapping dossier → thème pour métadonnées riches
FOLDER_THEME_MAP = {
    "mitre_attack":  "mitre",
    "cisa_kev":      "cisa",
    "nvd_cve":       "nvd",
    "threat_blogs":  "blog",
    "sigma_rules":   "sigma",
    "abuse_ch":      "abuse",
    "playbooks":     "playbook",
    "ssh":           "ssh",
    "dfir":          "dfir",
    "pivoting":      "pivoting",
    "detection":     "detection",
    "bash":          "bash",
    "hardening":     "hardening",
    "network":       "network",
    "reference":     "reference",
}

# ===================== INIT CLIENT =====================
client = chromadb.Client(settings=chromadb.config.Settings(
    persist_directory=DB_PATH,
    is_persistent=True
))


def get_collection():
    return client.get_or_create_collection(name="soc_elite")


collection = get_collection()


def get_embeddings():
    return OllamaEmbeddings(model=EMBED_MODEL)


# ===================== PARSE ARGS =====================
def parse_args():
    parser = argparse.ArgumentParser(description="SOC RAG Elite V2")
    parser.add_argument("--mode", type=str,
                        choices=["extract", "synthesis", "checklist", "red", "blue", "hunt"])
    parser.add_argument("--theme", type=str,
                        help="Filtrer par thème : mitre, cisa, sigma, blog, dfir, ssh...")
    parser.add_argument("--source", type=str, help="Filtrer par nom de fichier précis")
    parser.add_argument("--topk", type=int, default=8,
                        help="Nombre de chunks à récupérer (défaut : 8)")
    parser.add_argument("--question", type=str, help="Question à poser au RAG")
    parser.add_argument("--rebuild", action="store_true",
                        help="Reconstruire la base vectorielle")
    parser.add_argument("--stats", action="store_true",
                        help="Afficher les statistiques de la base")
    return parser.parse_args()


# ===================== MENU INTERACTIF =====================
def menu_interactif():
    print("\n" + "="*50)
    print("   SOC RAG ELITE V2 — Menu interactif")
    print("="*50)
    print("Modes disponibles :")
    print("  1) Extraction stricte  — commandes, configs, scripts exacts")
    print("  2) Synthèse experte    — explication pédagogique complète")
    print("  3) Checklist SOC       — liste opérationnelle prête à l'emploi")
    print("  4) Red Team            — attaques, pivoting, persistence, tunnels")
    print("  5) Blue Team           — détection, logs, audit, SIEM")
    print("  6) Threat Hunting      — hypothèses, IOC, requêtes de chasse")
    print()

    choice = input("Choisis un mode (1-6) : ").strip()
    mapping = {"1": "extract", "2": "synthesis", "3": "checklist",
               "4": "red", "5": "blue", "6": "hunt"}
    mode = mapping.get(choice, "synthesis")
    question = input("\nTa question : ").strip()

    print("\nThèmes disponibles : mitre, cisa, nvd, sigma, blog, dfir, ssh,")
    print("                     pivoting, detection, bash, hardening, network, playbook")
    theme = input("Filtrer par thème (Entrée pour tout chercher) : ").strip()

    topk = input("Chunks à récupérer (défaut 8) : ").strip()

    return {
        "mode": mode,
        "question": question,
        "theme": theme if theme else None,
        "topk": int(topk) if topk.isdigit() else 8,
        "source": None
    }


# ===================== DÉTECTION DU THÈME =====================
def detect_theme(filepath: str) -> str:
    """Détecte automatiquement le thème d'un fichier selon son chemin."""
    path_lower = filepath.lower().replace("\\", "/")
    for folder, theme in FOLDER_THEME_MAP.items():
        if folder in path_lower:
            return theme

    # Détection par mots-clés dans le nom du fichier
    fname = os.path.basename(path_lower)
    if re.search(r"t\d{4}", fname):       return "mitre"
    if "cve-" in fname:                    return "nvd"
    if "sigma" in fname:                   return "sigma"
    if "playbook" in fname:                return "playbook"
    if "ransomware" in fname:              return "dfir"
    if "ssh" in fname:                     return "ssh"
    if "network" in fname:                 return "network"

    return "general"


# ===================== BUILD DB =====================
def build_db():
    global collection

    print("\n" + "="*50)
    print("  REBUILD BASE VECTORIELLE")
    print("="*50)

    print("📚 Chargement des fichiers .txt et .md...")

    all_docs = []

    # Charger .txt
    for ext, glob_pattern in [("txt", "**/*.txt"), ("md", "**/*.md")]:
        try:
            from langchain_community.document_loaders import DirectoryLoader, TextLoader
            loader = DirectoryLoader(
                SOC_BRAIN_PATH,
                glob=glob_pattern,
                loader_cls=TextLoader,
                loader_kwargs={"encoding": "utf-8", "autodetect_encoding": True},
                silent_errors=True
            )
            docs = loader.load()
            all_docs.extend(docs)
            print(f"  ✅ {len(docs)} fichiers .{ext} chargés")
        except Exception as e:
            print(f"  ⚠️  Erreur chargement .{ext} : {e}")

    if not all_docs:
        print("❌ Aucun fichier trouvé dans ~/soc-brain")
        print("   Lance d'abord : python3 ~/soc_feed.py")
        return

    print(f"\n  📄 Total : {len(all_docs)} fichiers")

    # Chunking adaptatif selon le type de fichier
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=600,
        chunk_overlap=80,
        separators=["\n\n", "\n---\n", "\n", " "]
    )
    chunks = splitter.split_documents(all_docs)
    print(f"  🔪 {len(chunks)} chunks créés")

    print("\n🔢 Vectorisation en cours...")
    embeddings = get_embeddings()

    # Supprimer et recréer la collection
    try:
        client.delete_collection(name="soc_elite")
        print("  🗑️  Ancienne collection supprimée")
    except Exception:
        pass

    collection = client.get_or_create_collection(name="soc_elite")

    # Préparer les métadonnées enrichies
    texts     = [doc.page_content for doc in chunks]
    metadatas = []
    for i, doc in enumerate(chunks):
        source   = doc.metadata.get("source", "inconnu")
        basename = os.path.basename(source)
        theme    = detect_theme(source)

        metadatas.append({
            "source": basename,
            "theme":  theme,
            "path":   source,
        })

    # Insertion par batches
    total_batches = (len(chunks) + BATCH_SIZE - 1) // BATCH_SIZE
    print(f"\n  📦 Insertion par batches de {BATCH_SIZE}...")

    for i in tqdm(range(0, len(texts), BATCH_SIZE), total=total_batches, desc="Indexation"):
        batch_texts = texts[i:i + BATCH_SIZE]
        batch_metas = metadatas[i:i + BATCH_SIZE]
        batch_ids   = [str(i + j) for j in range(len(batch_texts))]

        # Vectoriser le batch
        batch_embeddings = embeddings.embed_documents(batch_texts)

        collection.add(
            documents=batch_texts,
            metadatas=batch_metas,
            ids=batch_ids,
            embeddings=batch_embeddings
        )

    print(f"\n✅ Base vectorielle créée — {len(chunks)} chunks indexés")
    print(f"   Fichiers : {len(all_docs)}")
    print(f"   Thèmes   : {sorted(set(m['theme'] for m in metadatas))}")


# ===================== STATS =====================
def show_stats():
    """Affiche les statistiques de la base vectorielle."""
    try:
        count = collection.count()
        print(f"\n📊 STATISTIQUES BASE VECTORIELLE")
        print(f"  Collection : soc_elite")
        print(f"  Chunks indexés : {count}")
        print(f"  Modèle embed   : {EMBED_MODEL}")
        print(f"  Modèle LLM     : {LLM_MODEL}")
        print(f"  DB path        : {DB_PATH}")
    except Exception as e:
        print(f"⚠️  Impossible de lire les stats : {e}")


# ===================== RETRIEVAL =====================
def retrieval(question: str, theme: str = None, topk: int = 8, source: str = None):
    """Recherche sémantique dans la base vectorielle."""
    embeddings = get_embeddings()
    query_embedding = embeddings.embed_query(question)

    # Filtre optionnel par thème
    where_filter = {"theme": theme} if theme else None

    try:
        results = collection.query(
            query_embeddings=[query_embedding],
            n_results=topk,
            where=where_filter
        )
    except Exception as e:
        print(f"⚠️  Erreur de requête : {e}")
        return [], []

    docs    = []
    sources = set()

    for doc, meta in zip(results["documents"][0], results["metadatas"][0]):
        src = meta.get("source", "inconnu")
        if source and src != source:
            continue
        docs.append(doc)
        sources.add(f"{src} [{meta.get('theme', '?')}]")

    return docs, list(sources)


# ===================== PROMPT BUILDER =====================
def build_prompt(docs: list, mode: str, question: str, sources: list) -> str:
    """Construit le prompt selon le mode sélectionné."""

    base = f"""Tu es un expert SOC/DFIR/RedTeam/BlueTeam senior avec 10 ans d'expérience.
Tu réponds en français, de manière précise et opérationnelle.
Mode actuel : {mode.upper()}
Question : {question}
Sources consultées : {', '.join(sources)}

"""

    instructions = {
        "extract": """INSTRUCTIONS — MODE EXTRACTION STRICTE :
- Utilise UNIQUEMENT les informations présentes dans les documents fournis
- Si une information n'est PAS dans les documents, écris : "Non mentionné dans les sources"
- INTERDIT d'inventer des commandes, Event IDs, extensions de fichiers ou règles
- Cite le nom exact du fichier source après chaque information
- Structure : ## Commandes ## Configuration ## Détection ## Scripts
""",
        "synthesis": """INSTRUCTIONS — MODE SYNTHÈSE EXPERTE :
- Synthèse pédagogique complète et claire
- Explique le POURQUOI avant le COMMENT
- Structure : contexte → mécanisme → étapes → points d'attention
- Inclus des exemples concrets
""",
        "checklist": """INSTRUCTIONS — MODE CHECKLIST SOC :
- Génère une checklist opérationnelle prête à l'emploi
- Format : □ item actionnable
- Sections : À faire immédiatement / À vérifier / À documenter
- Chaque item doit être concret et testable
""",
        "red": """INSTRUCTIONS — MODE RED TEAM :
- Extrais les vecteurs d'attaque, techniques d'exploitation
- Identifie les chemins de pivoting et de persistence
- Mentionne les outils associés (Metasploit, CobaltStrike, Impacket...)
- Référence les techniques MITRE ATT&CK correspondantes
- Format : Technique | Outil | Commande | ID ATT&CK
""",
        "blue": """INSTRUCTIONS — MODE BLUE TEAM :
- Extrais les méthodes de détection et de réponse
- Identifie les Event IDs Windows, les logs Linux, les règles Sigma
- Mentionne les requêtes SIEM (KQL/SPL)
- Indique les IOC et les artefacts forensiques à chercher
- Format : Menace | Détection | Log source | Event ID | Sigma Rule
""",
        "hunt": """INSTRUCTIONS — MODE THREAT HUNTING :
- Génère des hypothèses de chasse structurées
- Format par hypothèse : 
  HYPOTHÈSE : ...
  DONNÉES : quels logs/sources
  REQUÊTE : la requête concrète
  IOC : indicateurs à chercher
- Base-toi sur les techniques ATT&CK et les patterns connus
""",
    }

    prompt = base + instructions.get(mode, instructions["synthesis"])
    prompt += "\n===== DOCUMENTS À ANALYSER =====\n\n"
    prompt += "\n\n---\n\n".join(docs)
    prompt += "\n\n===== FIN DES DOCUMENTS =====\n\nRéponds maintenant :"

    return prompt


# ===================== LLM =====================
def ask_ollama(prompt: str) -> str:
    from llm_config import get_llm
    try:
        llm = get_llm()
        response = llm.invoke(prompt)
        return response.content if hasattr(response, "content") else response
    except Exception as e:
        return f"❌ Erreur LLM : {e}"

# ===================== DISPLAY =====================
def display_response(response: str, sources: list, mode: str, question: str):
    print("\n" + "="*60)
    print(f"  SOC RAG ELITE V2 — {mode.upper()}")
    print("="*60)
    print(f"  Question : {question}")
    print("="*60 + "\n")
    print(response)
    print("\n" + "="*60)
    print("  SOURCES CONSULTÉES")
    print("="*60)
    for s in sorted(sources):
        print(f"  • {s}")
    print()


# ===================== MAIN =====================
def main():
    args = parse_args()

    if args.stats:
        show_stats()
        return

    if args.rebuild:
        build_db()
        if not args.mode and not args.question:
            return

    if not args.mode or not args.question:
        inputs = menu_interactif()
        mode     = inputs["mode"]
        question = inputs["question"]
        theme    = inputs["theme"]
        topk     = inputs["topk"]
        source   = inputs["source"]
    else:
        mode     = args.mode
        question = args.question
        theme    = args.theme
        topk     = args.topk
        source   = args.source

    if not question:
        print("⚠️  Aucune question fournie.")
        return

    print(f"\n🔍 Recherche en cours... (topk={topk}" + (f", thème={theme}" if theme else "") + ")")
    docs, sources = retrieval(question, theme, topk, source)

    if not docs:
        print("⚠️  Aucun document trouvé.")
        print("   Si la base est vide, lance : python3 ~/soc_ask_v2.py --rebuild")
        return

    print(f"📄 {len(docs)} chunks trouvés dans {len(sources)} source(s)")
    print("🤖 Génération de la réponse...\n")

    prompt   = build_prompt(docs, mode, question, sources)
    response = ask_ollama(prompt)

    display_response(response, sources, mode, question)


if __name__ == "__main__":
    main()
