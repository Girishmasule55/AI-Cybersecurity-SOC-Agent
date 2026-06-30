from pathlib import Path

from app.core.config import get_settings


PLAYBOOKS = [
    {
        "id": "brute-force",
        "text": "Brute force response: block source IP, reset affected account password, check successful logins after failures, enable MFA, and review SSH exposure.",
    },
    {
        "id": "privilege-escalation",
        "text": "Privilege escalation response: isolate host, inspect sudo and admin group changes, collect process tree, rotate credentials, and verify patch level.",
    },
    {
        "id": "malware",
        "text": "Malware response: quarantine endpoint, preserve volatile evidence, identify persistence, remove payload, restore from clean backups, and hunt for indicators.",
    },
    {
        "id": "exfiltration",
        "text": "Data exfiltration response: disable suspect tokens, inspect outbound traffic, identify accessed data, notify stakeholders, and preserve network logs.",
    },
]


class PlaybookRAG:
    def __init__(self) -> None:
        settings = get_settings()
        Path(settings.chroma_dir).mkdir(parents=True, exist_ok=True)
        self.collection = None
        try:
            import chromadb
            from chromadb.utils import embedding_functions

            embedding = embedding_functions.SentenceTransformerEmbeddingFunction(
                model_name="all-MiniLM-L6-v2"
            )
            client = chromadb.PersistentClient(path=settings.chroma_dir)
            self.collection = client.get_or_create_collection(
                name="soc_playbooks",
                embedding_function=embedding,
            )
            self._seed()
        except Exception:
            self.collection = None

    def _seed(self) -> None:
        if self.collection is None:
            return
        existing = self.collection.count()
        if existing:
            return
        self.collection.add(
            ids=[item["id"] for item in PLAYBOOKS],
            documents=[item["text"] for item in PLAYBOOKS],
        )

    def retrieve(self, query: str, n_results: int = 3) -> list[str]:
        if self.collection is None:
            terms = query.lower().split()
            ranked = sorted(
                PLAYBOOKS,
                key=lambda item: sum(term in item["text"].lower() for term in terms),
                reverse=True,
            )
            return [item["text"] for item in ranked[:n_results]]
        results = self.collection.query(query_texts=[query], n_results=n_results)
        return results.get("documents", [[]])[0]
