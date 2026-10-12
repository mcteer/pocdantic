"""Bounded SELECT admission and trusted compilation, never execution of source SQL."""

import asyncio
import re
import sys

from pydantic import ValidationError

from agent.security import SecurityError

from .models import Order, Predicate, ReadPlan


def parse(request):
    """Lower the reviewed SQL subset to a closed plan inside the isolated parser worker."""
    import sqlglot
    from sqlglot import exp

    text = request.sql
    if not re.fullmatch(r"[A-Za-z0-9_.$*<>=!(),;\s]+", text, flags=re.ASCII):
        raise ValueError()
    if ";" in text.rstrip().removesuffix(";"):
        raise ValueError()
    allowed_words = {
        "select",
        "from",
        "where",
        "and",
        "order",
        "by",
        "asc",
        "desc",
        "limit",
        "group",
        "count",
        "id",
        "status",
        "public",
        "poc_records",
    }
    if any(w.lower() not in allowed_words for w in re.findall(r"[A-Za-z_][A-Za-z_0-9]*", text)):
        raise ValueError()
    tree = sqlglot.parse_one(text, read="postgres", error_level=sqlglot.ErrorLevel.RAISE)
    fields = {
        exp.Select: {"expressions", "from_", "where", "order", "limit", "group"},
        exp.From: {"this"},
        exp.Table: {"this", "db"},
        exp.Column: {"this"},
        exp.Identifier: {"this", "quoted"},
        exp.Count: {"this", "big_int"},
        exp.Star: set(),
        exp.Where: {"this"},
        exp.And: {"this", "expression"},
        exp.Paren: {"this"},
        exp.Parameter: {"this"},
        exp.Literal: {"this", "is_string"},
        exp.Order: {"expressions"},
        exp.Ordered: {"this", "desc", "nulls_first"},
        exp.Limit: {"expression"},
        exp.Group: {"expressions"},
        **{x: {"this", "expression"} for x in (exp.EQ, exp.NEQ, exp.LT, exp.LTE, exp.GT, exp.GTE)},
    }
    nodes = list(tree.walk())
    if len(nodes) > 256:
        raise ValueError()
    for node in nodes:
        if type(node) not in fields or node.depth > 16 or node.comments:
            raise ValueError()
        if any(
            k not in fields[type(node)] and v not in (None, False, []) for k, v in node.args.items()
        ):
            raise ValueError()
        if isinstance(node, exp.Identifier) and node.args.get("quoted"):
            raise ValueError()
        if isinstance(node, exp.Literal) and node.is_string:
            raise ValueError()
    if type(tree) is not exp.Select:
        raise ValueError()
    table = tree.args["from_"].this
    if (
        type(table) is not exp.Table
        or table.name.lower() != "poc_records"
        or table.db.lower() not in ("", "public")
    ):
        raise ValueError()

    def column(node):
        """Read only an unqualified, approved column node."""
        if type(node) is not exp.Column:
            raise ValueError()
        return node.name.lower()

    def count(node):
        """Recognize the single permitted function form."""
        return type(node) is exp.Count and type(node.this) is exp.Star

    expressions = tree.expressions
    group = tree.args.get("group")
    if len(expressions) == 1 and count(expressions[0]) and group is None:
        kind, columns = "count", ()
    elif len(expressions) == 2 and column(expressions[0]) == "status" and count(expressions[1]):
        if group is None or len(group.expressions) != 1 or column(group.expressions[0]) != "status":
            raise ValueError()
        kind, columns = "grouped_count", ()
    else:
        if group:
            raise ValueError()
        kind, columns = "rows", tuple(column(e) for e in expressions)
    predicates = []
    operators = {
        exp.EQ: "eq",
        exp.NEQ: "ne",
        exp.LT: "lt",
        exp.LTE: "le",
        exp.GT: "gt",
        exp.GTE: "ge",
    }

    def predicate(node):
        """Flatten only AND/parentheses; no arbitrary boolean expression survives."""
        if type(node) is exp.Paren:
            return predicate(node.this)
        if type(node) is exp.And:
            predicate(node.this)
            predicate(node.expression)
            return
        if type(node) not in operators or type(node.expression) is not exp.Parameter:
            raise ValueError()
        index = node.expression.this
        if type(index) is not exp.Literal or not re.fullmatch(r"[1-9][0-9]?", index.this):
            raise ValueError()
        predicates.append(
            Predicate(
                column=column(node.this),
                operator=operators[type(node)],
                parameter_index=int(index.this),
            )
        )

    if tree.args.get("where"):
        predicate(tree.args["where"].this)
    order = []
    if tree.args.get("order"):
        for term in tree.args["order"].expressions:
            if type(term) is not exp.Ordered:
                raise ValueError()
            order.append(
                Order(
                    column=column(term.this), direction="desc" if term.args.get("desc") else "asc"
                )
            )
    limit = 100
    if tree.args.get("limit"):
        item = tree.args["limit"].expression
        if type(item) is not exp.Literal or not re.fullmatch(r"[0-9]+", item.this):
            raise ValueError()
        limit = int(item.this)
    return ReadPlan(
        kind=kind,
        columns=columns,
        predicates=tuple(predicates),
        order=tuple(order),
        limit=limit,
        parameters=request.parameters,
    )


async def admit(request):
    """Killable parser protocol with private bounded frames and closed errors."""
    process = None
    try:
        async with asyncio.timeout(1):
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-I",
                "-m",
                "agent.sandbox.sql_worker",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                env={"PYTHONUTF8": "1"},
            )
            process.stdin.write(request.model_dump_json().encode())
            await process.stdin.drain()
            process.stdin.close()
            data = await process.stdout.read(16385)
            if len(data) > 16384:
                raise ValueError()
            await process.wait()
            if process.returncode:
                raise ValueError()
            return ReadPlan.model_validate_json(data)
    except (TimeoutError, ValueError, OSError, ValidationError):
        raise SecurityError("sandbox_query_denied") from None
    finally:
        if process and process.returncode is None:
            process.kill()
            await asyncio.shield(process.wait())


def compile_plan(plan):
    """Generate fresh SQL solely from closed enums; bind every data value separately."""
    plan = ReadPlan.model_validate_json(plan.model_dump_json())
    projection = (
        ", ".join(plan.columns)
        if plan.kind == "rows"
        else ("pg_catalog.count(*)" if plan.kind == "count" else "status, pg_catalog.count(*)")
    )
    sql = "SELECT " + projection + " FROM ONLY public.poc_records"
    values = []
    operators = {"eq": "=", "ne": "<>", "lt": "<", "le": "<=", "gt": ">", "ge": ">="}
    if plan.predicates:
        sql += " WHERE " + " AND ".join(
            p.column + " " + operators[p.operator] + " %s" for p in plan.predicates
        )
        values.extend(plan.parameters[p.parameter_index - 1] for p in plan.predicates)
    if plan.kind == "grouped_count":
        sql += " GROUP BY status"
    if plan.order:
        sql += " ORDER BY " + ", ".join(o.column + " " + o.direction.upper() for o in plan.order)
    sql += " LIMIT %s"
    values.append(1 if plan.kind == "count" else plan.limit + 1)
    return sql, tuple(values)
