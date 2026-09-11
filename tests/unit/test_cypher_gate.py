"""Unit tests for the read-only Cypher gate."""
from __future__ import annotations

import pytest

from throughline.graph.cypher_gate import FORBIDDEN_KEYWORDS, check_readonly
from throughline.graph.store import QueryRejected


def test_accepts_plain_read_and_injects_limit() -> None:
    assert check_readonly("MATCH (a:Alert) RETURN a.id") == "MATCH (a:Alert) RETURN a.id LIMIT 200"
    assert check_readonly("MATCH (a:Alert) RETURN a.id", row_limit=50) == "MATCH (a:Alert) RETURN a.id LIMIT 50"
    assert check_readonly("  RETURN 1 AS x ;  ") == "RETURN 1 AS x LIMIT 200"


def test_clamps_final_limit_only() -> None:
    assert check_readonly("MATCH (a) RETURN a.id LIMIT 100000", row_limit=200).endswith("LIMIT 200")
    assert check_readonly("MATCH (a) RETURN a.id LIMIT 5", row_limit=200).endswith("LIMIT 5")
    out = check_readonly("MATCH (a) WITH a LIMIT 7 RETURN a.id", row_limit=200)
    assert "WITH a LIMIT 7" in out and out.endswith("RETURN a.id LIMIT 200")
    out = check_readonly("MATCH (a) RETURN a.id ORDER BY a.id SKIP 10 LIMIT 999", row_limit=100)
    assert out.endswith("SKIP 10 LIMIT 100")
    out = check_readonly("MATCH (a) RETURN a.id LIMIT 10\nUNION\nMATCH (b) RETURN b.id", row_limit=20)
    assert out.endswith("RETURN b.id LIMIT 20")


def test_limit_must_be_literal() -> None:
    with pytest.raises(QueryRejected, match="LIMIT"):
        check_readonly("MATCH (a) RETURN a LIMIT $n")
    with pytest.raises(QueryRejected, match="LIMIT"):
        check_readonly("MATCH (a) RETURN a LIMIT 10 + 5")


@pytest.mark.parametrize(
    "query",
    [
        "CREATE (n:Alert {id: 'x'})",
        "MATCH (a) SET a.x = 1 RETURN a",
        "MATCH (a) DELETE a",
        "MATCH (a) DETACH DELETE a",
        "MATCH (a) REMOVE a.x RETURN a",
        "MERGE (n:Alert {id: 'x'}) RETURN n",
        "DROP TABLE Alert",
        "ALTER TABLE Alert ADD foo STRING",
        "COPY Alert FROM 'x.parquet'",
        "LOAD FROM 'x.csv' RETURN *",
        "MATCH (a) WITH a LOAD FROM 'x.csv' RETURN *",
        "INSTALL fts",
        "ATTACH 'x' AS y (dbtype duckdb)",
        "CALL show_tables() RETURN *",
        "MATCH (a) CALL { WITH a RETURN a.id AS x } RETURN x",
        "IMPORT DATABASE '/tmp/x'",
        "EXPORT DATABASE '/tmp/x'",
        "BEGIN TRANSACTION",
        "COMMIT",
        "MATCH (a) FOREACH (x IN [1] | SET a.y = x) RETURN a",
        "EXPLAIN MATCH (a) RETURN a",
        "PROFILE MATCH (a) RETURN a",
        "USE graph MATCH (a) RETURN a",
        "SHOW DATABASES",
    ],
)
def test_rejects_write_ddl_procedure_keywords(query: str) -> None:
    with pytest.raises(QueryRejected):
        check_readonly(query)


def test_keywords_inside_literals_comments_and_property_names_are_fine() -> None:
    assert check_readonly("MATCH (a) WHERE a.title CONTAINS 'CREATE MERGE DELETE' RETURN a.title").startswith("MATCH")
    assert check_readonly('MATCH (a) WHERE a.title = "SET" RETURN a.title').startswith("MATCH")
    assert check_readonly("MATCH (a) WHERE a.set = 1 AND a.load IS NULL RETURN a.copy, a.call").startswith("MATCH")
    out = check_readonly("MATCH (a) // CREATE is only a comment here\nRETURN a.id /* DELETE */")
    assert "CREATE" not in out and "DELETE" not in out and out.endswith("LIMIT 200")
    assert check_readonly("MATCH (g:`Group`) RETURN g.name").startswith("MATCH")
    with pytest.raises(QueryRejected, match="unterminated"):
        check_readonly("MATCH (a) WHERE a.x = 'oops RETURN a")


def test_rejects_multiple_statements_and_non_read_start() -> None:
    with pytest.raises(QueryRejected, match="multiple statements"):
        check_readonly("MATCH (a) RETURN a; MATCH (b) RETURN b")
    with pytest.raises(QueryRejected, match="must start with"):
        check_readonly("WHERE a.x = 1 RETURN a")
    with pytest.raises(QueryRejected, match="empty"):
        check_readonly("   ")
    with pytest.raises(QueryRejected, match="empty"):
        check_readonly(";")
    assert check_readonly("OPTIONAL MATCH (a) RETURN a.id").startswith("OPTIONAL MATCH")
    assert check_readonly("UNWIND [1,2] AS x RETURN x").startswith("UNWIND")
    assert check_readonly("WITH 1 AS x RETURN x").startswith("WITH")


@pytest.mark.parametrize(
    "pattern",
    ["[*]", "[e*]", "[:CAN_ASSUME*]", "[e:CAN_ASSUME|CAN_ACCESS*]", "[*1..]", "[*2..]", "[*1..6]", "[*..6]", "[*7]", "[e* SHORTEST 1..8]", "[e* ALL SHORTEST 2..]"],
)
def test_rejects_unbounded_or_too_long_variable_length(pattern: str) -> None:
    with pytest.raises(QueryRejected):
        check_readonly(f"MATCH (a)-{pattern}->(b) RETURN a.id, b.id")


@pytest.mark.parametrize(
    "pattern",
    ["[*1..5]", "[*..5]", "[*2]", "[:CAN_ASSUME*0..2]", "[e:CAN_ASSUME|CAN_ACCESS*1..3]", "[e* SHORTEST 1..5]", "[e* ALL SHORTEST 1..3]", "[e* WSHORTEST(confidence) 1..3]", "[e*1..3 (r, n | WHERE label(r) IN ['CAN_ASSUME'])]", "[e* SHORTEST 1..3 (r, n | WHERE n.id <> 'x')]"],
)
def test_accepts_bounded_variable_length(pattern: str) -> None:
    assert check_readonly(f"MATCH (a)-{pattern}->(b) RETURN a.id, b.id").endswith("LIMIT 200")


def test_max_var_length_is_configurable() -> None:
    assert check_readonly("MATCH (a)-[*1..8]->(b) RETURN a.id", max_var_length=8)
    with pytest.raises(QueryRejected):
        check_readonly("MATCH (a)-[*1..3]->(b) RETURN a.id", max_var_length=2)


def test_quantified_path_patterns() -> None:
    assert check_readonly("MATCH ((a)-[:CAN_ASSUME]->(b)){1,3} RETURN a.id")
    for bad in ["MATCH ((a)-[:CAN_ASSUME]->(b)){1,} RETURN a.id", "MATCH ((a)-[:CAN_ASSUME]->(b)){2,9} RETURN a.id", "MATCH ((a)-[:CAN_ASSUME]->(b))+ RETURN a.id", "MATCH ((a)-[:CAN_ASSUME]->(b))* RETURN a.id"]:
        with pytest.raises(QueryRejected):
            check_readonly(bad)
    # arithmetic groups are not path quantifiers
    assert check_readonly("MATCH (a) RETURN (a.x + 1) * (a.y + 2) AS z, count(*)").endswith("LIMIT 200")


def test_star_outside_patterns_is_not_a_traversal() -> None:
    assert check_readonly("MATCH (a) RETURN count(*)").endswith("LIMIT 200")
    assert check_readonly("MATCH (a) RETURN a.x * 2 AS doubled").endswith("LIMIT 200")
    assert check_readonly("MATCH (a) WHERE a.list = [1 * 2] RETURN a").endswith("LIMIT 200")


def test_forbidden_list_contains_contract_keywords() -> None:
    required = {"CREATE", "MERGE", "SET", "DELETE", "REMOVE", "DROP", "ALTER", "COPY", "LOAD", "INSTALL", "ATTACH", "DETACH", "CALL", "IMPORT", "EXPORT", "BEGIN", "COMMIT"}
    assert required <= FORBIDDEN_KEYWORDS


def test_bad_configuration_raises_value_error() -> None:
    with pytest.raises(ValueError):
        check_readonly("MATCH (a) RETURN a", max_var_length=0)
    with pytest.raises(ValueError):
        check_readonly("MATCH (a) RETURN a", row_limit=0)
