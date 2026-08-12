"""Chroma-backed persistence."""

from __future__ import annotations

import json
import os
from pathlib import Path

import chromadb
import structlog

from peekaboo.schemas import Report

log = structlog.get_logger(__name__)

# Disable Chroma telemetry before client import side effects
os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")


class PersistenceStore:
    COLLECTION_DESC = "artifacts.desc"
    COLLECTION_REPORTS = "rca.reports"

    def __init__(self, db_dir: Path) -> None:
        db_dir.mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(path=str(db_dir))
        self._desc = self._client.get_or_create_collection(self.COLLECTION_DESC)
        self._reports = self._client.get_or_create_collection(self.COLLECTION_REPORTS)

    def get_cached_report(self, cve: str) -> Report | None:
        results = self._reports.get(where={"cve": cve}, limit=1)
        if not results["ids"]:
            return None
        data = json.loads(results["documents"][0])
        return Report.model_validate(data)

    def save_report(self, report: Report) -> None:
        doc_id = f"{report.cve}:{report.file_name}:{report.function_address}"
        self._reports.upsert(
            ids=[doc_id],
            documents=[report.model_dump_json()],
            metadatas=[{
                "cve": report.cve,
                "platform": report.platform,
                "file_name": report.file_name,
                "confidence": report.confidence,
            }],
        )
        log.info("report_saved", cve=report.cve, file=report.file_name)

    def save_file_description(self, key: str, description: str, metadata: dict) -> None:
        self._desc.upsert(
            ids=[key],
            documents=[description],
            metadatas=[metadata],
        )

    def query_descriptions(self, query: str, n: int = 10) -> list[dict]:
        if self._desc.count() == 0:
            return []
        results = self._desc.query(query_texts=[query], n_results=min(n, self._desc.count()))
        out = []
        for i, doc_id in enumerate(results["ids"][0]):
            out.append({
                "id": doc_id,
                "description": results["documents"][0][i],
                "metadata": results["metadatas"][0][i],
                "distance": results["distances"][0][i] if results.get("distances") else 0.0,
            })
        return out

    def list_reports(self, cve: str | None = None) -> list[Report]:
        where = {"cve": cve} if cve else None
        results = self._reports.get(where=where)
        reports = []
        for doc in results.get("documents") or []:
            if doc:
                reports.append(Report.model_validate(json.loads(doc)))
        return reports
