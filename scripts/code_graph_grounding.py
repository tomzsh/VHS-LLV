#!/usr/bin/env python3
"""Verify Graph-RAG citations against an exported Code-Graph-RAG graph.

The verifier is deliberately deterministic: it does not ask an LLM to decide
whether a citation exists. Claims without valid node/edge citations are marked
un-grounded so downstream reporting can treat them as UNKNOWN.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any


def key(value: Any) -> str:
    return str(value)


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def load_graph(path: Path) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    data = read_json(path)
    raw_nodes = data.get("nodes")
    raw_relationships = data.get("relationships")
    if not isinstance(raw_nodes, list) or not isinstance(raw_relationships, list):
        raise ValueError("graph must contain list fields 'nodes' and 'relationships'")
    nodes: dict[str, dict[str, Any]] = {}
    for item in raw_nodes:
        if not isinstance(item, dict) or "node_id" not in item:
            raise ValueError("every graph node needs node_id")
        nodes[key(item["node_id"])] = item
    relationships = [item for item in raw_relationships if isinstance(item, dict)]
    return nodes, relationships


def node_properties(node: dict[str, Any]) -> dict[str, Any]:
    value = node.get("properties")
    return value if isinstance(value, dict) else {}


def node_summary(node: dict[str, Any]) -> dict[str, Any]:
    props = node_properties(node)
    result = {
        "node_id": node.get("node_id"),
        "labels": node.get("labels") or [],
        "qualified_name": props.get("qualified_name"),
        "name": props.get("name"),
        "path": props.get("path"),
        "start_line": props.get("start_line"),
        "end_line": props.get("end_line"),
    }
    return {name: value for name, value in result.items() if value is not None}


def validate_node_citation(
    citation: dict[str, Any], nodes: dict[str, dict[str, Any]], repo: Path | None
) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    node_id = citation.get("node_id")
    if node_id is None:
        return None, ["node citation is missing node_id"]
    node = nodes.get(key(node_id))
    if node is None:
        return None, [f"node_id {node_id} is not present in graph"]
    props = node_properties(node)
    expected_name = citation.get("qualified_name")
    if expected_name is not None and props.get("qualified_name") != expected_name:
        errors.append(
            f"node_id {node_id} qualified_name mismatch: "
            f"expected {expected_name!r}, graph has {props.get('qualified_name')!r}"
        )
    expected_path = citation.get("path")
    if expected_path is not None and props.get("path") != expected_path:
        errors.append(
            f"node_id {node_id} path mismatch: expected {expected_path!r}, "
            f"graph has {props.get('path')!r}"
        )
    for field in ("start_line", "end_line"):
        if field in citation and citation[field] != props.get(field):
            errors.append(
                f"node_id {node_id} {field} mismatch: expected {citation[field]!r}, "
                f"graph has {props.get(field)!r}"
            )
    if repo and props.get("path"):
        source = (repo / str(props["path"])).resolve()
        try:
            source.relative_to(repo.resolve())
        except ValueError:
            errors.append(f"node_id {node_id} source path escapes repository")
        else:
            if not source.is_file():
                errors.append(f"node_id {node_id} source file is missing: {props['path']}")
            else:
                lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
                start = props.get("start_line")
                end = props.get("end_line")
                if isinstance(start, int) and isinstance(end, int) and not (1 <= start <= end <= len(lines)):
                    errors.append(
                        f"node_id {node_id} line range {start}-{end} exceeds "
                        f"{props['path']} ({len(lines)} lines)"
                    )
    summary = node_summary(node)
    if repo and props.get("path") and not errors:
        source = (repo / str(props["path"])).resolve()
        if source.is_file():
            summary["source_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    return summary, errors


def validate_edge_citation(
    citation: dict[str, Any], nodes: dict[str, dict[str, Any]], relationships: list[dict[str, Any]]
) -> tuple[dict[str, Any] | None, list[str]]:
    source = citation.get("from_node_id")
    target = citation.get("to_node_id")
    rel_type = citation.get("type")
    errors: list[str] = []
    if source is None or target is None or not rel_type:
        return None, ["edge citation requires from_node_id, to_node_id, and type"]
    if key(source) not in nodes:
        errors.append(f"edge source node_id {source} is not present in graph")
    if key(target) not in nodes:
        errors.append(f"edge target node_id {target} is not present in graph")
    match = next(
        (
            item
            for item in relationships
            if key(item.get("from_id")) == key(source)
            and key(item.get("to_id")) == key(target)
            and item.get("type") == rel_type
        ),
        None,
    )
    if match is None:
        errors.append(f"edge {source} -[{rel_type}]-> {target} is not present in graph")
        return None, errors
    return {
        "from_node_id": source,
        "to_node_id": target,
        "type": rel_type,
        "properties": match.get("properties") or {},
    }, errors


def verify(args: argparse.Namespace) -> int:
    nodes, relationships = load_graph(args.graph)
    claims = read_json(args.claims)
    citations = claims.get("citations")
    errors: list[str] = []
    validated: list[dict[str, Any]] = []
    if not isinstance(citations, list) or not citations:
        errors.append("claims must contain at least one citation")
    else:
        for index, raw in enumerate(citations):
            if not isinstance(raw, dict):
                errors.append(f"citation {index} is not an object")
                continue
            if "node_id" in raw:
                item, item_errors = validate_node_citation(raw, nodes, args.repo)
            else:
                item, item_errors = validate_edge_citation(raw, nodes, relationships)
            errors.extend(f"citation {index}: {message}" for message in item_errors)
            if item is not None and not item_errors:
                validated.append(item)
    output = {
        "grounded": bool(validated) and not errors,
        "status": "SUPPORTED" if bool(validated) and not errors else "UNKNOWN",
        "answer": claims.get("answer"),
        "validated_citations": validated,
        "errors": errors,
        "graph": {
            "node_count": len(nodes),
            "relationship_count": len(relationships),
        },
    }
    rendered = json.dumps(output, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
        try:
            args.output.chmod(0o600)
        except OSError:
            pass
    print(rendered, end="")
    return 0 if output["grounded"] else 1


def context(args: argparse.Namespace) -> int:
    nodes, relationships = load_graph(args.graph)
    root = nodes.get(key(args.node_id))
    if root is None:
        print(json.dumps({"grounded": False, "status": "UNKNOWN", "errors": [f"node_id {args.node_id} is not present in graph"]}, indent=2))
        return 1
    selected = {key(args.node_id)}
    edges = []
    for rel in relationships:
        if key(rel.get("from_id")) == key(args.node_id) or key(rel.get("to_id")) == key(args.node_id):
            edges.append(rel)
            selected.add(key(rel.get("from_id")))
            selected.add(key(rel.get("to_id")))
    output = {
        "grounded": True,
        "status": "RETRIEVED",
        "retrieval_contract": "Use only these nodes and edges; cite node_id or from_node_id/to_node_id/type.",
        "nodes": [node_summary(nodes[item]) for item in sorted(selected) if item in nodes],
        "relationships": edges,
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    verify_parser = sub.add_parser("verify", help="verify claims against a graph export")
    verify_parser.add_argument("--graph", type=Path, required=True)
    verify_parser.add_argument("--claims", type=Path, required=True)
    verify_parser.add_argument("--repo", type=Path, help="optional repo root for source path/line checks")
    verify_parser.add_argument("--output", type=Path)
    verify_parser.set_defaults(handler=verify)
    context_parser = sub.add_parser("context", help="retrieve one-hop graph context for grounded RAG")
    context_parser.add_argument("--graph", type=Path, required=True)
    context_parser.add_argument("--node-id", required=True)
    context_parser.set_defaults(handler=context)
    args = parser.parse_args()
    try:
        return args.handler(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"grounded": False, "status": "UNKNOWN", "errors": [str(exc)]}, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
