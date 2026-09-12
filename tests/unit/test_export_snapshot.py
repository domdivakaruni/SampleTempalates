"""Static snapshot exporter (scripts/export_snapshot.py, docs/10-static-snapshot.md): runs the exporter once into a
tmp dir with small caps and checks the file set, coverage rules and normalisation the adapter relies on. Skipped when
the generated dataset is missing (`make data`); about 30 s otherwise."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from throughline.config import settings
from throughline.simulator import storyline_constants as C

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA = Path(settings.data_dir)
MAX_FILE_BYTES = 15 * 1_000_000
pytestmark = pytest.mark.skipif(not (DATA / "graph" / "nodes.jsonl").exists(), reason="generated dataset missing; run `make data`")


def _load_exporter():
    spec = importlib.util.spec_from_file_location("export_snapshot", REPO_ROOT / "scripts" / "export_snapshot.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve the module's postponed annotations through sys.modules
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def exporter():
    return _load_exporter()


@pytest.fixture(scope="module")
def out_dir(tmp_path_factory: pytest.TempPathFactory, exporter) -> Path:
    out = tmp_path_factory.mktemp("snapshot") / "snapshot-out"
    rc = exporter.main(["--out", str(out), "--data", str(DATA), "--top-contexts", "5", "--max-chat-answers", "8"])
    assert rc == 0
    return out


def _read(out_dir: Path, rel: str) -> Any:
    return json.loads((out_dir / rel).read_text(encoding="utf-8"))


def test_manifest_and_shards(out_dir: Path) -> None:
    manifest = _read(out_dir, "manifest.json")
    for key in ("version", "generated_at", "seed", "node_count", "edge_count", "alert_count", "shards", "notes"):
        assert key in manifest, key
    assert manifest["version"] == 1
    assert manifest["shards"]["alert_details"] and manifest["shards"]["edges"]
    for rel in manifest["shards"]["alert_details"] + manifest["shards"]["edges"]:
        assert (out_dir / rel).is_file(), rel
    for rel in ("meta.json", "alerts.json", "storylines.json", "ti.json", "investigate.json", "graph/nodes.json",
                "graph/blast_radius.json", "graph/attack_paths.json", "node_cards.json", "search.json", "chat.json"):
        assert (out_dir / rel).is_file(), rel
    assert "normalisation" in manifest["notes"].lower() or "normalization" in manifest["notes"].lower()


def test_every_file_under_cap(out_dir: Path) -> None:
    sizes = {p.relative_to(out_dir).as_posix(): p.stat().st_size for p in out_dir.rglob("*.json")}
    too_big = {k: v for k, v in sizes.items() if v >= MAX_FILE_BYTES}
    assert not too_big, too_big


def test_meta_is_snapshot_flavoured(out_dir: Path) -> None:
    meta = _read(out_dir, "meta.json")
    assert meta["health"]["backend"] == "snapshot"
    assert meta["health"]["agent_mode"] == "offline" and meta["health"]["analyst_mode"] == "precomputed"
    assert meta["stats"]["backend"] == "snapshot" and meta["stats"]["capabilities"]["cypher"] is False
    assert meta["schema"]["labels"] and meta["schema"]["edge_types"]
    assert meta["dashboard"]["rerank_examples"]


def test_alerts_and_details_cover_every_alert(out_dir: Path) -> None:
    manifest = _read(out_dir, "manifest.json")
    alerts = _read(out_dir, "alerts.json")["items"]
    nodes = _read(out_dir, "graph/nodes.json")["nodes"]
    alert_nodes = {n["id"] for n in nodes if n["label"] == "Alert"}
    ids = [a["id"] for a in alerts]
    assert len(ids) == len(set(ids)) == manifest["alert_count"] == len(alert_nodes)
    assert set(ids) == alert_nodes
    # contextual order, as GET /alerts returns it
    scores = [a["contextual_score"] for a in alerts]
    assert scores == sorted(scores, reverse=True)
    covered: set[str] = set()
    for rel in manifest["shards"]["alert_details"]:
        shard = _read(out_dir, rel)
        for aid, entry in shard.items():
            assert hashlib.sha1(aid.encode()).hexdigest()[: manifest["alert_shard_prefix_len"]] == Path(rel).stem
            assert set(entry) >= {"alert", "flat_view", "risk", "insights"}
            covered.add(aid)
    assert covered == set(ids)


def test_storyline_member_has_full_context_and_others_are_lite(out_dir: Path) -> None:
    manifest = _read(out_dir, "manifest.json")
    a009 = C.ALERT_A["a009"][0]
    shard = _read(out_dir, f"alert_details/{hashlib.sha1(a009.encode()).hexdigest()[:manifest['alert_shard_prefix_len']]}.json")
    ctx = shard[a009]["context"]
    assert ctx["alert"]["id"] == a009 and ctx["storyline"]["id"] == C.STORYLINE_A
    assert ctx["evidence"]["nodes"] and ctx["blast_radius"]["crown_jewels"]
    assert len(ctx["evidence"]["nodes"]) <= 150 and len(ctx["evidence"]["edges"]) <= 400
    with_context = sum("context" in e for rel in manifest["shards"]["alert_details"] for e in _read(out_dir, rel).values())
    assert with_context == manifest["coverage"]["alerts_with_context"]
    assert with_context < manifest["alert_count"]  # --top-contexts 5 keeps only the mandatory alerts plus the top 5


def test_chat_demo_question_8(out_dir: Path, exporter) -> None:
    chat = _read(out_dir, "chat.json")
    question = exporter.DEMO_QUESTIONS[7]
    assert "credentials" in question
    entries = [e for e in chat["answers"] if e["context_key"] == "" and e["normalized"] == exporter.normalize_question(question)]
    assert len(entries) == 1, [e["normalized"] for e in chat["answers"]]
    entry = entries[0]
    assert entry["question"] == question
    assert entry["normalized"] == "which credentials used in cloud api calls today were seen being stolen on an endpoint"
    assert C.CRED_BASTION_KEY in entry["answer"]["narrative_md"]
    assert entry["answer"]["mode"] == "offline"
    assert all(tc["duration_ms"] == 0 for tc in entry["answer"]["tool_calls"])
    assert len(entry["answer"]["evidence"]["nodes"]) <= 120 and len(entry["answer"]["evidence"]["edges"]) <= 300
    assert len(chat["answers"]) <= 8
    assert chat["suggestions"][""] == list(exporter.DEMO_QUESTIONS)
    assert f"storyline:{C.STORYLINE_A}" in chat["suggestions"]


def test_normalisation_rule(exporter) -> None:
    norm = exporter.normalize_question
    assert norm("Why is `alert:falcon:ldt-a009` risky? Explain its contextual score.") == "why is alert:falcon:ldt-a009 risky explain its contextual score."
    assert norm("  Is the 'S3 bucket public' critical finding actually risky - what's in it?  ") == "is the s3 bucket public critical finding actually risky - whats in it"
    assert norm("What is `credential:ssh:dwhitfield-id_ed25519`?") == "what is credential:ssh:dwhitfield-id_ed25519"


def test_graph_counts_match_manifest(out_dir: Path) -> None:
    manifest = _read(out_dir, "manifest.json")
    nodes = _read(out_dir, "graph/nodes.json")["nodes"]
    assert len(nodes) == manifest["node_count"] == len({n["id"] for n in nodes})
    for n in nodes[:200]:
        assert set(n) >= {"id", "label", "name", "category", "props", "tags"}
        assert "raw" not in n["props"] and "score_breakdown" not in n["props"]
    edges = [e for rel in manifest["shards"]["edges"] for e in _read(out_dir, rel)["edges"]]
    assert len(edges) == manifest["edge_count"] == meta_total_edges(out_dir)
    src, etype, dst, derived, confidence = edges[0]
    assert isinstance(src, str) and isinstance(etype, str) and isinstance(dst, str)
    assert derived in (0, 1) and isinstance(confidence, float)
    search = _read(out_dir, "search.json")["entries"]
    assert len(search) == manifest["node_count"]
    bastion = next(e for e in search if e[0] == C.EP_BASTION)
    assert bastion[1] == "Endpoint" and C.BASTION_PRIVATE_IP in bastion[5]


def meta_total_edges(out_dir: Path) -> int:
    return int(_read(out_dir, "meta.json")["stats"]["total_edges"])


def test_analytics_coverage(out_dir: Path) -> None:
    storylines = _read(out_dir, "storylines.json")
    assert {s["id"] for s in storylines["items"]} == {C.STORYLINE_A, C.STORYLINE_B}
    assert all(s.get("fragment") is None for s in storylines["items"])
    assert storylines["details"][C.STORYLINE_A]["fragment"]["nodes"]
    ti = _read(out_dir, "ti.json")
    assert C.ACTOR_CJ in ti["actor_details"] and C.CAMPAIGN_EMBERCAST in ti["campaign_details"] and C.REPORT_EMBERCAST in ti["report_details"]
    assert ti["lookups"][C.C2_IP]["matches"] and ti["lookups"]["cinder jackal"]["actors"]
    assert ti["lookups"]["cve-2021-44228"]["exploited_vulnerabilities"] and "t1190" in ti["lookups"]
    assert ti["exposure"]["sector_only"]["items"] and ti["exposure"]["all"]["items"]
    inv = _read(out_dir, "investigate.json")
    assert inv["credential_joins"]["items"]
    assert "" in inv["alerts_reaching_crown_jewels"] and C.CARDHOLDER_VAULT in inv["alerts_reaching_crown_jewels"]
    assert set(inv["medium_alerts_with_data_path"]) == {"medium|falcon", "medium|", "high|falcon", "low|falcon"}
    assert C.BASTION_ROLE in inv["identity_footprint"] and len(inv["identity_footprint"]) <= 60
    sims = {(tuple(c["targets"]), tuple(c["actions"])) for c in inv["containment"]}
    assert ((C.EP_BASTION, C.BASTION_ROLE), ("isolate_endpoint", "rotate_role_credentials")) in sims
    assert ((C.EP_EDGE,), ("isolate_endpoint",)) in sims and len(sims) == 17
    blast = _read(out_dir, "graph/blast_radius.json")
    assert C.EP_BASTION in blast and C.BASTION_ROLE in blast
    assert all(len(b["fragment"]["nodes"]) <= 100 for b in blast.values())
    paths = _read(out_dir, "graph/attack_paths.json")
    assert C.ALERT_A["a009"][0] in paths and f"internet->{C.CARDHOLDER_VAULT}" in paths
    cards = _read(out_dir, "node_cards.json")
    assert C.EP_BASTION in cards and C.ACTOR_CJ in cards and len(cards) <= 400
    assert cards[C.EP_BASTION]["node"]["id"] == C.EP_BASTION and "degree" in cards[C.EP_BASTION]
