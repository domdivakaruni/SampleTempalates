"""Command line: ``throughline serve | ask | build-data | demo``.

Imports are lazy so ``throughline --help`` works even while heavy packages (analytics, graph backends) are being
built or are not installed.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path


def _settings():  # noqa: ANN202 - lazy
    from throughline.config import settings

    return settings


def _configure_logging(level: str) -> None:
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO), format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    settings = _settings()
    host = args.host or settings.api_host
    port = args.port or settings.api_port
    uvicorn.run("throughline.api.app:create_app", factory=True, host=host, port=port, reload=bool(args.reload), log_level=settings.log_level.lower())
    return 0


def cmd_ask(args: argparse.Namespace) -> int:
    from throughline.api.runtime import load_runtime

    settings = _settings()
    rt = load_runtime(settings)
    if rt.analyst is None:
        print(f"error: the analyst is not available ({rt.error}). Run `throughline build-data` first.", file=sys.stderr)
        return 2
    context = {k: v for k, v in {"alert_id": args.alert, "storyline_id": args.storyline, "selected_node_ids": [args.node] if args.node else None}.items() if v}
    answer = rt.analyst.answer(args.question, context or None, args.mode)
    if args.json:
        print(answer.model_dump_json(indent=2))
        return 0
    print(answer.narrative_md.rstrip())
    print()
    print(
        f"-- mode={answer.mode} intent={answer.intent or '-'} model={answer.model or '-'} confidence={answer.confidence:.2f} "
        f"| evidence: {len(answer.evidence.nodes)} nodes, {len(answer.evidence.edges)} edges, {len(answer.evidence.paths)} paths "
        f"| findings: {len(answer.findings)} | tool calls: {len(answer.tool_calls)}"
    )
    for call in answer.tool_calls:
        flag = " (error)" if call.error else ""
        print(f"   {call.name}({json.dumps(call.arguments, default=str)}) -> {call.summary}{flag}")
    if answer.followups:
        print("-- follow-ups:")
        for q in answer.followups:
            print(f"   - {q}")
    rt.close()
    return 0


def cmd_build_data(args: argparse.Namespace) -> int:
    settings = _settings()
    try:
        from throughline.simulator import build as build_mod  # integration module
    except ImportError:
        print(
            "The simulator pipeline (throughline.simulator.build) is not available in this checkout.\n"
            f"Expected canonical graph files at {Path(settings.data_dir) / 'graph'} (nodes.jsonl, edges.jsonl, manifest.json).\n"
            "Generate them with `python -m throughline.simulator.build` once the simulator is integrated.",
            file=sys.stderr,
        )
        return 1
    main = getattr(build_mod, "main", None)
    if main is None:
        print("throughline.simulator.build has no main(); nothing to run", file=sys.stderr)
        return 1
    try:
        rc = main()
    except TypeError:
        rc = main([])
    return int(rc or 0)


def cmd_demo(args: argparse.Namespace) -> int:
    settings = _settings()
    nodes = Path(settings.data_dir) / "graph" / "nodes.jsonl"
    if not nodes.is_file():
        print(f"no graph data at {nodes}; building the dataset first ...")
        rc = cmd_build_data(args)
        if rc != 0:
            print("data build did not succeed; starting the server anyway (health will report degraded)", file=sys.stderr)
    return cmd_serve(args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="throughline", description="Throughline security context graph prototype")
    parser.add_argument("--log-level", default=None, help="override LOG_LEVEL")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the API (and the built web UI) with uvicorn")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)
    serve.add_argument("--reload", action="store_true")
    serve.set_defaults(func=cmd_serve)

    ask = sub.add_parser("ask", help="ask the analyst a question from the terminal")
    ask.add_argument("question")
    ask.add_argument("--alert", default=None, help="alert id used as canvas context ('this alert')")
    ask.add_argument("--storyline", default=None, help="storyline id used as context")
    ask.add_argument("--node", default=None, help="selected node id used as context")
    ask.add_argument("--mode", choices=["offline", "llm", "auto"], default=None)
    ask.add_argument("--json", action="store_true", help="print the AnalystAnswer as JSON")
    ask.set_defaults(func=cmd_ask)

    build = sub.add_parser("build-data", help="generate the simulated dataset (throughline.simulator.build)")
    build.set_defaults(func=cmd_build_data)

    demo = sub.add_parser("demo", help="build data if missing, then serve")
    demo.add_argument("--host", default=None)
    demo.add_argument("--port", type=int, default=None)
    demo.add_argument("--reload", action="store_true")
    demo.set_defaults(func=cmd_demo)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(args.log_level or _settings().log_level)
    return int(args.func(args) or 0)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
