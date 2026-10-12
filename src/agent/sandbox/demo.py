"""Fixed offline programs exercise real Monty; database effects are explicitly synthetic."""

from .runner import SandboxExecution

RECORDS = ((1, "open"), (2, "open"), (3, "closed"), (4, "pending"))
PROGRAMS = {
    "filtered-rows": (
        'r = await query_database("SELECT id, status FROM poc_records WHER'
        'E id > $1 ORDER BY id", [2])\n[x["id"] for x in r["rows"]]'
    ),
    "grouped-counts": (
        'r = await query_database("SELECT status, COUNT(*) FROM poc_record'
        's GROUP BY status", [])\n{x["status"]:x["count"] for x in r["rows"'
        "]}"
    ),
    "percentages": (
        'r = await query_database("SELECT status, COUNT(*) FROM poc_record'
        's GROUP BY status", [])\nn = sum(x["count"] for x in r["rows"])\n{x'
        '["status"]:100*x["count"]/n for x in r["rows"]} if n else {}'
    ),
    "host-file": "open('/private/host-canary').read()",
    "host-environment": "import os\nos.getenv('MONTY_SECRET_CANARY')",
    "host-callback-reflection": "query_database.__globals__",
    "host-socket": "import socket\nsocket.create_connection(('remote.example',22))",
    "remote-ssh": "import subprocess\nsubprocess.run(['ssh','remote.example','uname'])",
    "remote-library": "import paramiko\nparamiko.SSHClient()",
    "remote-function": "run_remote_command('remote.example','uname')",
    "sql-write": 'await query_database("DELETE FROM poc_records", [])',
    "sql-statements": (
        'await query_database("SELECT id FROM poc_records; DELETE FROM poc_records", [])'
    ),
    "sql-table": 'await query_database("SELECT id FROM unauthorized", [])',
    "sql-function": 'await query_database("SELECT pg_sleep(1) FROM poc_records", [])',
    "sql-cte": (
        'await query_database("WITH x AS (SELECT id FROM poc_records) SELECT id FROM x", [])'
    ),
    "sql-lock": 'await query_database("SELECT id FROM poc_records FOR UPDATE", [])',
    "compute-limit": "while True: pass",
    "memory-limit": '"x" * 100000000',
    "output-limit": 'print("x" * 20000)',
    "calls-limit": "\n".join(
        'await query_database("SELECT COUNT(*) FROM poc_records", [])' for _ in range(4)
    ),
    "partial-denial": (
        'await query_database("SELECT COUNT(*) FROM poc_records", [])\nawai'
        't query_database("DELETE FROM poc_records", [])'
    ),
}


async def synthetic_query(plan):
    """Evaluate only the closed plan over synthetic records; no connection or Vault client."""
    selected = []
    operators = {
        "eq": lambda a, b: a == b,
        "ne": lambda a, b: a != b,
        "lt": lambda a, b: a < b,
        "le": lambda a, b: a <= b,
        "gt": lambda a, b: a > b,
        "ge": lambda a, b: a >= b,
    }
    for record_id, status in RECORDS:
        row = {"id": record_id, "status": status}
        if all(
            operators[p.operator](row[p.column], plan.parameters[p.parameter_index - 1])
            for p in plan.predicates
        ):
            selected.append(row)
    if plan.kind == "count":
        rows = [{"count": len(selected)}]
    elif plan.kind == "grouped_count":
        counts = {}
        for row in selected:
            counts[row["status"]] = counts.get(row["status"], 0) + 1
        rows = [{"status": status, "count": count} for status, count in counts.items()]
    else:
        rows = [{column: r[column] for column in plan.columns} for r in selected]
    for order in reversed(plan.order):
        rows.sort(key=lambda r: r[order.column], reverse=order.direction == "desc")
    return {
        "rows": rows[: plan.limit],
        "row_count": min(len(rows), plan.limit),
        "truncated": len(rows) > plan.limit,
    }


async def demonstration():
    """Return metadata assertions; raw programs/results never enter the emitted report."""
    from agent.security import SecurityError

    expected = {
        "filtered-rows": [3, 4],
        "grouped-counts": {"open": 2, "closed": 1, "pending": 1},
        "percentages": {"open": 50.0, "closed": 25.0, "pending": 25.0},
    }
    cases = []
    for name, code in PROGRAMS.items():
        execution = SandboxExecution(synthetic_query, lambda: None)
        value = None
        try:
            value = await execution.execute(code)
        except SecurityError:
            pass
        if name in expected:
            passed = execution.completed and value == expected[name] and execution.reads == 1
            boundary = "database"
        elif name.startswith("sql-"):
            passed = (
                not execution.completed
                and execution.failure == "sandbox_query_denied"
                and execution.admitted == 0
            )
            boundary = "query_policy"
        elif name in ("calls-limit", "partial-denial"):
            passed = not execution.completed and execution.reads == (
                3 if name == "calls-limit" else 1
            )
            boundary = "query_policy"
        else:
            passed = not execution.completed and execution.attempted == 0
            boundary = "sandbox"
        passed = passed and execution.exercised
        cases.append(
            {
                "case_id": name,
                "origin": "synthetic",
                "engine": "monty",
                "outcome": "pass" if passed else "fail",
                "boundary": boundary,
                "query_attempted": execution.attempted,
                "query_admitted": execution.admitted,
                "reads": execution.reads,
                "credentials_acquired": 0,
                "remote_connections": 0,
                "reason": execution.failure,
            }
        )
    return {
        "schema_version": 1,
        "origin": "synthetic",
        "engine": "monty",
        "completed": len(cases),
        "cases": cases,
        "passed": all(c["outcome"] == "pass" for c in cases),
    }
