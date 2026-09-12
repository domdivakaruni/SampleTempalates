"""Run the twelve demo questions through the analyst and print the answers (offline by default).

Usage: .venv/bin/python scripts/demo_questions.py [--mode offline|llm|auto] [--only 1,5,8] [--json]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from throughline.config import settings  # noqa: E402

QUESTIONS = [
    "Show me everything connected to the credential-dumping alert on BAS-01 - what can an attacker reach from here?",
    "Which of today's medium-severity endpoint alerts sit on assets with a path to regulated data?",
    "Is the cloud API activity from the bastion role in the last 6 hours related to any endpoint detection?",
    "What is the blast radius if identity LarkspurBastionSSMRole is fully compromised?",
    "Which internet-exposed hosts have a vuln a threat actor is actively exploiting against fintechs right now?",
    "Rank all open alerts by contextual risk, not vendor severity, and explain the top 3.",
    "Trace the full attack path from the phishing detection on WKS-3391 to any regulated data store.",
    "Which credentials used in cloud API calls today were seen being stolen on an endpoint?",
    "Do any current detections match IOCs or TTPs from the Cinder Jackal report, and what do they touch?",
    "Show only alerts on assets that can reach cardholder data; hide everything else.",
    "Is the 'S3 bucket public' critical finding actually risky - what's in it and can an actor reach it?",
    "If we isolate BAS-01 and rotate the bastion role now, what do we contain and what breaks?",
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default="offline", choices=["offline", "llm", "auto"])
    ap.add_argument("--only", default="", help="comma-separated question numbers")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    from throughline.agent.analyst import Analyst
    from throughline.agent.tools import ToolRegistry
    from throughline.analytics.engine import AnalyticsEngine
    from throughline.graph.factory import make_store
    from throughline.graph.loader import load_context_graph

    t0 = time.perf_counter()
    graph = load_context_graph(Path(settings.data_dir))
    engine = AnalyticsEngine(graph)
    store = make_store(settings, graph)
    analyst = Analyst(ToolRegistry(engine, store), mode=args.mode)
    print(f"[loaded {len(graph)} nodes / {graph.G.number_of_edges()} edges in {time.perf_counter() - t0:.1f}s; backend={getattr(store, 'name', '?')}; mode={args.mode}]\n")

    wanted = {int(x) for x in args.only.split(",") if x.strip()} if args.only else set(range(1, len(QUESTIONS) + 1))
    out = []
    for i, q in enumerate(QUESTIONS, start=1):
        if i not in wanted:
            continue
        t1 = time.perf_counter()
        answer = analyst.answer(q, context={}, mode=args.mode)
        dt = time.perf_counter() - t1
        if args.json:
            out.append({"n": i, "question": q, "answer": answer.model_dump(), "seconds": round(dt, 2)})
            continue
        print("=" * 100)
        print(f"Q{i}. {q}")
        print(f"[{answer.mode} | intent={answer.intent} | {len(answer.tool_calls)} tool calls | evidence {len(answer.evidence.nodes)} nodes / {len(answer.evidence.edges)} edges | {dt:.2f}s]")
        print("-" * 100)
        print(answer.narrative_md.strip())
        if answer.followups:
            print("\nFollow-ups: " + " | ".join(answer.followups))
        print()
    if args.json:
        print(json.dumps(out, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
