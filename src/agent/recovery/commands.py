"""Operator recovery CLI with safe summaries and explicit enrollment.

Commands use the fixed project root and existing settings. Administrative credentials
are used only by explicit cleanup, never printed or persisted in journal records.
"""

import asyncio
import json
from uuid import UUID

import httpx

from agent.settings import Settings
from agent.vault import VaultClient

from .models import REASONS, Receipt
from .proof import read_source, verify_sources
from .store import RecoveryError, RecoveryStore


def add_recovery_parser(subparsers):
    """Register explicit recovery commands without alternate roots, token arguments, or reset."""
    parser = subparsers.add_parser(
        "recover", help="Inspect or reconcile private credential recovery"
    )
    commands = parser.add_subparsers(dest="recovery_command", required=True)
    commands.add_parser(
        "init", help="Enroll future live database attempts; does not repair incidents"
    )
    commands.add_parser("migrate", help="Offline lossless recovery state migration")
    commands.add_parser("status", help="Inspect recovery without provider requests")
    review = commands.add_parser("import", help="Verify reviewed private native evidence")
    review.add_argument("--incident", dest="incident_id", required=True, type=UUID)
    review.add_argument(
        "--source",
        dest="sources",
        action="append",
        required=True,
        help="Private file below .local; at most two",
    )
    review.add_argument("--reviewer", required=True, help="Non-sensitive provenance reviewer label")
    revoke = commands.add_parser("revoke", help="Synchronously clean up one exact known lease")
    revoke.add_argument("--incident", dest="incident_id", required=True, type=UUID)


def result(store, status, *, reason=None, incident_id=None):
    """Build a sanitized CLI summary from authoritative state without native identifiers."""
    view = store.status()
    reason = reason or view.reason_code
    return {
        "status": status,
        "recovery": view.recovery,
        "blocked": view.recovery not in {"clear", "not_configured"},
        "reason_code": reason,
        "next_action": REASONS[reason][1] if reason else None,
        "incident_id": str(incident_id) if incident_id else None,
        "incidents": [item.model_dump(mode="json") for item in view.incidents],
    }


async def execute_recovery(args, *, settings=None, project=None, transport=None):
    """Execute one explicit operator command, returning safe JSON and a bounded exit status."""
    store = RecoveryStore(settings or Settings(), project=project)
    try:
        if args.recovery_command == "init":
            changed = store.initialize()
            output = result(store, "initialized" if changed else "unchanged")
            code = 0
        elif args.recovery_command == "migrate":
            store.migrate()
        elif args.recovery_command in {"import", "revoke"}:
            with store.effect():
                journal = store.read()
                item = next(
                    (a for a in journal.attempts if a.incident_id == args.incident_id), None
                )
                if item is None:
                    raise RecoveryError("recovery_evidence_invalid")
                if args.recovery_command == "import":
                    if not 1 <= len(args.sources) <= 2 or not 0 < len(args.reviewer.strip()) <= 64:
                        raise RecoveryError("recovery_evidence_invalid")
                    if item.state == "resolved":
                        # A repeat validates unchanged provenance; it never rewrites a receipt.
                        if (
                            not item.receipt
                            or not item.receipt.source_digests
                            or args.reviewer.strip() != item.receipt.reviewer_label
                            or tuple(read_source(store, p)[1] for p in args.sources)
                            != item.receipt.source_digests
                        ):
                            raise RecoveryError("recovery_evidence_invalid")
                    else:
                        proof = verify_sources(store, item, args.sources, args.reviewer)
                        terminal = proof.receipt.outcome in {"revoked", "not_issued"}
                        previous = item.receipt
                        if (
                            previous
                            and previous.source_digests
                            and not set(previous.source_digests)
                            <= set(proof.receipt.source_digests)
                        ):
                            raise RecoveryError("recovery_evidence_invalid")
                        repeated = (
                            previous
                            and previous.outcome == proof.receipt.outcome
                            and previous.source_digests == proof.receipt.source_digests
                            and previous.reviewer_label == proof.receipt.reviewer_label
                        )
                        if not repeated:
                            store.update(
                                item.incident_id,
                                item.revision,
                                state="resolved" if terminal else "unresolved",
                                lease_handle=proof.lease_handle,
                                native_request_id=proof.receipt.native_request_id,
                                receipt=proof.receipt,
                                resolution=proof.receipt.outcome if terminal else None,
                                reason_code="cleanup_unconfirmed"
                                if proof.lease_handle
                                else item.reason_code,
                            )
                elif item.state != "resolved":
                    await revoke_exact(store, item, transport=transport)
                output = result(
                    store,
                    "unchanged"
                    if item.state == "resolved"
                    else "reviewed"
                    if args.recovery_command == "import"
                    else "revoked",
                    incident_id=item.incident_id,
                )
                code = 0
        else:
            view = store.status()
            owned = ()
            if view.recovery in {"clear", "blocked"}:
                owned = tuple(a.incident_id for a in store.read().attempts if a.state != "resolved")
                view = store.status(owned=owned)
            output = result(store, "inspected") | {
                "incidents": [a.model_dump(mode="json") for a in view.incidents]
            }
            code = (
                0
                if view.recovery in {"clear", "not_configured"}
                else 2
                if view.recovery in {"blocked", "uninitialized"}
                or view.reason_code == "recovery_busy"
                else 1
            )
        print(json.dumps(output))
        return code
    except RecoveryError as error:
        reason = str(error)
        print(json.dumps(result(store, "blocked", reason=reason)))
        return (
            2
            if reason
            in {
                "recovery_uninitialized",
                "recovery_busy",
                "recovery_evidence_required",
                "recovery_access_denied",
            }
            else 1
        )


async def revoke_exact(store, item, *, transport=None):
    """Use existing administrative authority only for this durable exact handle.

    Cancellation retains the caller's effect lock until the HTTP worker drains. Intent
    precedes the call; a timeout or failed receipt leaves the incident blocked.
    """
    if not item.lease_handle:
        raise RecoveryError("recovery_evidence_required")
    token = store.settings.vault_token
    if not token:
        raise RecoveryError("recovery_access_denied")
    item = store.update(item.incident_id, item.revision, state="cleanup_pending")
    async with httpx.AsyncClient(
        timeout=10, follow_redirects=False, trust_env=False, transport=transport
    ) as http:
        vault = VaultClient(store.settings.vault_addr, store.settings.vault_namespace, http)
        worker = asyncio.create_task(
            vault.revoke(token, item.lease_handle)
            if transport is not None
            else isolated_revoke(store, item, token)
        )
        failure = None
        try:
            done, _ = await asyncio.wait({worker}, timeout=10)
            if not done:
                raise RecoveryError("cleanup_unconfirmed")
            worker.result()
        except BaseException as error:
            failure = error
        finally:
            if not worker.done():
                worker.cancel()
            while not worker.done():
                try:
                    await asyncio.shield(worker)
                except asyncio.CancelledError:
                    continue
                except Exception:
                    break
        if failure is not None:
            store.update(
                item.incident_id,
                item.revision,
                state="unresolved",
                reason_code="cleanup_unconfirmed",
            )
            if isinstance(failure, asyncio.CancelledError):
                raise failure
            reason = (
                "recovery_access_denied"
                if str(failure) in {"vault_http_401", "vault_http_403", "recovery_access_denied"}
                else "cleanup_unconfirmed"
            )
            raise RecoveryError(reason) from None
        receipt = Receipt(
            outcome="revoked",
            incident_id=item.incident_id,
            incident_revision=item.revision,
            operation_id=item.operation_id,
            environment_digest=item.environment_digest,
            native_request_id=item.native_request_id,
            native_response_id=item.native_request_id,
            source_digests=item.receipt.source_digests if item.receipt else (),
            reviewer_label=item.receipt.reviewer_label if item.receipt else None,
            reviewed_at=item.receipt.reviewed_at if item.receipt else None,
        )
        store.update(
            item.incident_id, item.revision, state="resolved", resolution="revoked", receipt=receipt
        )


async def isolated_revoke(store, item, token):
    """Send private cleanup inputs through stdin to a terminable production worker."""
    from .workers import network_process

    payload = json.dumps(
        {
            "address": store.settings.vault_addr,
            "namespace": store.settings.vault_namespace,
            "lease": item.lease_handle,
            "token": token.get_secret_value(),
        }
    ).encode()
    async with network_process(
        __name__,
        "cleanup-worker",
        ownership_fds=tuple(owner.fd for owner in store.owners if owner.active),
    ) as process:
        raw, _ = await process.communicate(payload)
        if process.returncode != 0 or raw != b"revoked":
            raise RecoveryError(
                "recovery_access_denied" if raw == b"denied" else "cleanup_unconfirmed"
            )


async def cleanup_worker():
    """Perform one exact cleanup; emit only a closed result and discard private inputs."""
    import sys

    from pydantic import SecretStr

    from agent.validation.store import decode_json

    try:
        data = decode_json(sys.stdin.buffer.read(8193))
        if set(data) != {"address", "namespace", "lease", "token"}:
            raise ValueError()
        async with httpx.AsyncClient(timeout=10, trust_env=False, follow_redirects=False) as http:
            vault = VaultClient(data["address"], data["namespace"], http)
            await vault.revoke(SecretStr(data["token"]), data["lease"])
        sys.stdout.write("revoked")
    except Exception as error:
        sys.stdout.write(
            "denied" if str(error) in {"vault_http_401", "vault_http_403"} else "unconfirmed"
        )


if __name__ == "__main__":
    import sys

    if sys.argv[1:] == ["cleanup-worker"]:
        asyncio.run(cleanup_worker())
