"""Normalized pytest hooks: retain node text only in child memory and require all phases."""

import hashlib
import os
from datetime import UTC, datetime

import pytest

from .models import Frame, RegressionError, canonical, digest


class Reporter:
    """Write bounded sequential metadata, never exception bodies or captured output."""

    def __init__(self, fd, identity, selectors, guard, item_limit=10000):
        """Bind exact compiled selection and fresh source identity before collection."""
        self.fd, self.identity, self.selectors, self.guard = fd, identity, selectors, guard
        self.item_limit = item_limit
        self.sequence = 0
        self.items = {}
        self.phases = {}
        self.starts = {}
        self.failed = False
        self.inventory = []

    def emit(self, kind, **values):
        """Validate and write one small frame; oversize metadata terminates the child."""
        self.sequence += 1
        frame = Frame(**self.identity, seq=self.sequence, kind=kind, **values)
        raw = (
            canonical(frame.model_dump(mode="json", exclude_none=True, exclude_defaults=True))
            + b"\n"
        )
        if len(raw) > 16 * 1024:
            raise RegressionError("limits_exceeded")
        while raw:
            raw = raw[os.write(self.fd, raw) :]

    @pytest.hookimpl(wrapper=True, tryfirst=True)
    def pytest_collection_modifyitems(self, session, config, items):
        """Compare exact expanded nodes before and after every collection hook."""
        before = [item.nodeid for item in items]
        yield
        if before != [item.nodeid for item in items] or len(before) != len(set(before)):
            self.failed = True
            self.emit("error", reason="selection_incomplete")

    def pytest_collectreport(self, report):
        """Collection failure carries only its classification, never import diagnostics."""
        if report.failed:
            self.failed = True
            self.emit("error", reason="collection_failed")

    def pytest_collection_finish(self, session):
        """Expand every selected function fully and seal the inventory with opaque hashes."""
        if len(session.items) > self.item_limit:
            self.failed = True
            self.emit("error", reason="limits_exceeded")
            pytest.exit("limits_exceeded", returncode=2)
        counts = dict.fromkeys(self.selectors, 0)
        for ordinal, item in enumerate(session.items, 1):
            selector = item.nodeid.split("[", 1)[0]
            if selector not in counts or ordinal > 10000:
                self.failed = True
                self.emit(
                    "error",
                    reason="selection_incomplete" if selector not in counts else "limits_exceeded",
                )
                continue
            counts[selector] += 1
            node = hashlib.sha256(item.nodeid.encode()).hexdigest()
            self.items[item.nodeid] = (selector, node, ordinal)
            self.inventory.append([selector, node, ordinal])
            self.emit("collection", selector=selector, node_digest=node, ordinal=ordinal)
        if not counts or not all(counts.values()):
            self.failed = True
            self.emit("error", reason="empty_selection")
        self.emit("collection", count=len(self.inventory), inventory_digest=digest(self.inventory))

    def pytest_runtest_logreport(self, report):
        """Require ordered setup/call/teardown and distinguish skip, xfail and xpass."""
        if report.nodeid not in self.items:
            self.failed = True
            self.emit("error", reason="protocol_invalid")
            return
        phases = self.phases.setdefault(report.nodeid, [])
        if report.when == "setup":
            self.starts[report.nodeid] = datetime.fromtimestamp(report.start, UTC).isoformat()
        expected = ("setup", "call", "teardown")
        # A failed/skipped setup omits call; it still cannot yield a complete pass.
        index = expected.index(report.when)
        while len(phases) < index:
            phases.append("missing")
        if len(phases) != index:
            self.failed = True
            self.emit("error", reason="protocol_invalid")
            return
        phase = "pass" if report.passed else "skip" if report.skipped else "fail"
        if hasattr(report, "wasxfail"):
            phase = "xpass" if report.passed else "xfail"
        phases.append(phase)
        if report.when == "teardown":
            selector, node, ordinal = self.items[report.nodeid]
            counters = {}
            for key, value in report.user_properties:
                if key in {"attempted", "issued", "completed", "forbidden"}:
                    if key in counters or type(value) is not int or not 0 <= value <= 10000:
                        self.failed = True
                        self.emit("error", reason="protocol_invalid")
                        return
                    counters[key] = value
            self.emit(
                "item",
                selector=selector,
                node_digest=node,
                ordinal=ordinal,
                phases=phases,
                counters=counters,
                started_at=self.starts.get(report.nodeid),
                finished_at=datetime.fromtimestamp(report.stop, UTC).isoformat(),
            )

    def pytest_sessionfinish(self, session, exitstatus):
        """Remember framework completion; final emission waits for all session hooks to return."""
        self.session_exit = int(exitstatus)

    def finish(self, exitstatus):
        """A terminal seal binds inventory and child exit; caught guard violations still fail."""
        if getattr(self, "session_exit", None) != exitstatus:
            self.failed = True
        reason = (
            "isolation_failed" if self.guard.failed else "protocol_invalid" if self.failed else None
        )
        self.emit(
            "terminal",
            count=len(self.items),
            inventory_digest=digest(self.inventory),
            exit_code=int(exitstatus),
            reason=reason,
        )
