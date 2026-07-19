"""MITRE ATT&CK knowledge base integration.

Provides structured access to the ATT&CK framework for use in agent planning,
context retrieval, and knowledge ingestion into the Qdrant vector store.

Key concepts:
    - Tactic (战术): The "why" — an attacker's strategic objective at a stage
    - Technique (技术): The "how" — a specific method to achieve a tactic
    - Sub-technique (子技术): A finer-grained refinement of a technique
    - Procedure (步骤): Real-world tool / command that implements a technique
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pooch
from mitreattack import release_info
from mitreattack.stix20 import MitreAttackData

from secmind.memory import MemoryDocument

STIX_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "attack-stix"


def _get_attack_id(obj: Any) -> str:
    """Extract ATT&CK ID from STIX object's external_references."""
    refs = obj.get("external_references") or []
    for ref in refs:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def _get_name(obj: Any) -> str:
    """Extract name from STIX object."""
    return obj.get("name", "")


class AttackKnowledgeBase:
    """MITRE ATT&CK knowledge base query interface.

    Lazily downloads the latest STIX bundle on first use, then caches it locally.
    Provides methods to browse tactics, techniques, and convert data for vector ingestion.
    """

    def __init__(
        self,
        domain: str = "enterprise",
        data_dir: str | Path | None = None,
    ) -> None:
        self.domain = domain
        self.data_dir = Path(data_dir or STIX_DATA_DIR)
        self._mitre: MitreAttackData | None = None

    @property
    def mitre(self) -> MitreAttackData:
        """Lazy-loaded MitreAttackData instance."""
        if self._mitre is None:
            self._ensure_downloaded()
            self._mitre = MitreAttackData(stix_filepath=str(self._stix_path()))
        return self._mitre

    # ----------------------------------------------------------------
    # Data download
    # ----------------------------------------------------------------

    def _ensure_downloaded(self) -> None:
        """Download the ATT&CK STIX bundle if not already cached."""
        latest = release_info.LATEST_VERSION
        if self.domain == "enterprise":
            hashes = release_info.STIX20["enterprise"]
        elif self.domain == "mobile":
            hashes = release_info.STIX20["mobile"]
        elif self.domain == "ics":
            hashes = release_info.STIX20["ics"]
        else:
            raise ValueError(f"Unknown domain: {self.domain}")

        known_hash = hashes.get(latest)
        if known_hash is None:
            raise RuntimeError(f"No hash found for ATT&CK v{latest} ({self.domain})")

        download_url = (
            f"https://raw.githubusercontent.com/mitre/cti/"
            f"ATT%26CK-v{latest}/{self.domain}-attack/{self.domain}-attack.json"
        )
        release_dir = self.data_dir / f"v{latest}"
        if self._stix_path().exists():
            return  # already downloaded
        release_dir.mkdir(parents=True, exist_ok=True)
        pooch.retrieve(
            download_url,
            known_hash=known_hash,
            fname=f"{self.domain}-attack.json",
            path=str(release_dir),
        )

    def _stix_path(self) -> Path:
        return self.data_dir / f"v{release_info.LATEST_VERSION}" / f"{self.domain}-attack.json"

    # ----------------------------------------------------------------
    # Query: tactics
    # ----------------------------------------------------------------

    def get_tactics(self) -> list[dict[str, Any]]:
        """Return all tactics with their ATT&CK ID, name, and description."""
        results: list[dict[str, Any]] = []
        for obj in self.mitre.get_tactics():
            results.append(
                {
                    "attack_id": _get_attack_id(obj),
                    "name": _get_name(obj),
                    "short_name": obj.get("x_mitre_shortname", ""),
                    "description": obj.get("description", ""),
                }
            )
        return results

    def get_tactics_by_matrix(self, matrix_name: str | None = None) -> list[dict[str, Any]]:
        """Return tactics belonging to a specific matrix (default: enterprise-attack)."""
        matrix = matrix_name or f"{self.domain}-attack"
        results: list[dict[str, Any]] = []
        for obj in self.mitre.get_tactics_by_matrix(matrix):
            results.append(
                {
                    "attack_id": _get_attack_id(obj),
                    "name": _get_name(obj),
                    "description": obj.get("description", ""),
                }
            )
        return results

    # ----------------------------------------------------------------
    # Query: techniques
    # ----------------------------------------------------------------

    def get_techniques(self) -> list[dict[str, Any]]:
        """Return all top-level techniques (excluding sub-techniques)."""
        return self._format_techniques(self.mitre.get_techniques(include_subtechniques=False))

    def get_all_techniques(self) -> list[dict[str, Any]]:
        """Return all techniques including sub-techniques (~600 entries in total)."""
        return self._format_techniques(self.mitre.get_techniques(include_subtechniques=True))

    def get_techniques_by_tactic(self, tactic_name: str) -> list[dict[str, Any]]:
        """Return techniques that belong to a given tactic (e.g. 'initial-access')."""
        domain = f"{self.domain}-attack"
        objs = self.mitre.get_techniques_by_tactic(tactic_name, domain=domain)
        return self._format_techniques(objs)

    def get_techniques_by_platform(self, platform: str) -> list[dict[str, Any]]:
        """Return techniques for a specific platform (e.g. 'windows', 'linux')."""
        objs = self.mitre.get_techniques_by_platform(platform)
        return self._format_techniques(objs)

    def get_technique(self, attack_id: str) -> dict[str, Any] | None:
        """Get a single technique by its ATT&CK ID (e.g. 'T1190')."""
        obj = self.mitre.get_object_by_attack_id(attack_id, stix_type="attack-pattern")
        if obj is None:
            return None
        return self._format_technique(obj)

    def search_techniques(self, query: str) -> list[dict[str, Any]]:
        """Search techniques by name or description content."""
        objs = self.mitre.get_objects_by_content(query, object_type="attack-pattern")
        return self._format_techniques(objs)

    # ----------------------------------------------------------------
    # Query: sub-techniques
    # ----------------------------------------------------------------

    def get_subtechniques(self, technique_id: str) -> list[dict[str, Any]]:
        """Return all sub-techniques of a given technique."""
        parent = self.mitre.get_object_by_attack_id(technique_id, stix_type="attack-pattern")
        if parent is None:
            return []
        prefix = f"{technique_id}."
        all_techs = self.mitre.get_techniques(include_subtechniques=True)
        subs = [t for t in all_techs if _get_attack_id(t).startswith(prefix)]
        return self._format_techniques(subs)

    # ----------------------------------------------------------------
    # Relationships
    # ----------------------------------------------------------------

    def get_mitigations(self, technique_id: str) -> list[dict[str, Any]]:
        """Return mitigations for a specific technique."""
        obj = self.mitre.get_object_by_attack_id(technique_id, stix_type="attack-pattern")
        if obj is None:
            return []
        mitigations = self.mitre.get_mitigations_mitigating_technique(obj)
        return [
            {
                "attack_id": _get_attack_id(m),
                "name": _get_name(m),
                "description": m.get("description", ""),
            }
            for m in mitigations
        ]

    # ----------------------------------------------------------------
    # Format helpers
    # ----------------------------------------------------------------

    def _format_techniques(self, objects: list[Any]) -> list[dict[str, Any]]:
        return [self._format_technique(obj) for obj in objects]

    @staticmethod
    def _format_technique(obj: Any) -> dict[str, Any]:
        attack_id = _get_attack_id(obj)
        kill_chain = obj.get("kill_chain_phases") or []
        tactics = [p.get("phase_name", "") for p in kill_chain]
        return {
            "attack_id": attack_id,
            "name": _get_name(obj),
            "description": obj.get("description", ""),
            "tactics": tactics,
            "platforms": list(obj.get("x_mitre_platforms", [])),
            "is_subtechnique": "/" in (attack_id or ""),
            "detection": obj.get("x_mitre_detection", ""),
            "data_sources": list(obj.get("x_mitre_data_sources", [])),
        }

    # ----------------------------------------------------------------
    # Conversion to vector-store documents
    # ----------------------------------------------------------------

    def to_memory_documents(
        self,
        techniques: list[dict[str, Any]] | None = None,
        version: str | None = None,
    ) -> list[MemoryDocument]:
        """Convert ATT&CK entries to MemoryDocuments for Qdrant ingestion.

        Args:
            techniques: List of technique dicts (from get_techniques*). If None, uses all.
            version: ATT&CK version string. Defaults to release_info.LATEST_VERSION.

        Returns:
            List of MemoryDocument objects ready for vector store upsert.
        """
        if techniques is None:
            techniques = self.get_techniques()
        version_str = version or release_info.LATEST_VERSION

        docs: list[MemoryDocument] = []
        for t in techniques:
            info_parts = [
                f"Technique: {t['attack_id']} - {t['name']}",
                f"描述: {t['description']}",
                f"战术阶段: {', '.join(t['tactics'])}",
                f"平台: {', '.join(t['platforms'])}",
            ]
            if t.get("detection"):
                info_parts.append(f"检测方法: {t['detection']}")
            if t.get("data_sources"):
                info_parts.append(f"数据源: {', '.join(t['data_sources'])}")

            docs.append(
                MemoryDocument(
                    content="\n".join(info_parts),
                    source="mitre-attack",
                    version=version_str,
                    kind="knowledge",
                    metadata={
                        "attack_id": t["attack_id"],
                        "technique_name": t["name"],
                        "tactics": t["tactics"],
                        "platforms": t["platforms"],
                        "is_subtechnique": t["is_subtechnique"],
                    },
                )
            )
        return docs

    def to_tactic_documents(
        self,
        tactics: list[dict[str, Any]] | None = None,
        version: str | None = None,
    ) -> list[MemoryDocument]:
        """Convert ATT&CK tactics to MemoryDocuments.

        Args:
            tactics: List of tactic dicts (from get_tactics). If None, loads all.
            version: ATT&CK version string.

        Returns:
            List of MemoryDocument objects for tactics.
        """
        if tactics is None:
            tactics = self.get_tactics()
        version_str = version or release_info.LATEST_VERSION

        docs: list[MemoryDocument] = []
        for t in tactics:
            info_parts = [
                f"Tactic: {t['attack_id']} - {t['name']}",
                f"描述: {t['description']}",
            ]

            docs.append(
                MemoryDocument(
                    content="\n".join(info_parts),
                    source="mitre-attack",
                    version=version_str,
                    kind="knowledge",
                    metadata={
                        "attack_id": t["attack_id"],
                        "tactic_name": t["name"],
                        "is_tactic": True,
                    },
                )
            )
        return docs

    def all_documents(self, version: str | None = None) -> list[MemoryDocument]:
        """Return all ATT&CK entries as MemoryDocuments: techniques, sub-techniques, and tactics.

        This is the recommended method for full ingestion — it yields ~600+ documents.
        """
        version_str = version or release_info.LATEST_VERSION
        all_techs = self.get_all_techniques()
        all_tactics = self.get_tactics()
        tech_docs = self.to_memory_documents(all_techs, version_str)
        tactic_docs = self.to_tactic_documents(all_tactics, version_str)
        return tech_docs + tactic_docs

    # ----------------------------------------------------------------
    # Summary
    # ----------------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        """Return a summary of the loaded ATT&CK data."""
        tactics = self.get_tactics()
        techniques = self.get_techniques()
        all_techs = self.get_all_techniques()
        sub_count = len(all_techs) - len(techniques)
        return {
            "domain": self.domain,
            "attack_version": release_info.LATEST_VERSION,
            "tactic_count": len(tactics),
            "technique_count": len(techniques),
            "subtechnique_count": sub_count,
            "total_count": len(all_techs) + len(tactics),
            "tactics": [t["name"] for t in tactics],
        }
