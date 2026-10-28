# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 AgentIM contributors
"""Native account creation transaction and initial-device authorization state."""

import hashlib
from typing import TYPE_CHECKING, Any

from synapse.api.errors import Codes, LoginError, SynapseError
from synapse.storage.databases.main.registration import LoginTokenLookupResult
from synapse.storage.engines import PostgresEngine

if TYPE_CHECKING:
    from synapse.server import HomeServer
    from synapse.storage.database import LoggingTransaction


def digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class InitialAccountStore:
    def __init__(self, hs: "HomeServer") -> None:
        self.hs = hs
        self.native = hs.get_datastores().main
        self.pool = self.native.db_pool

    async def binding(self, attempt_id: str) -> tuple[Any, ...] | None:
        def read(txn: "LoggingTransaction") -> tuple[Any, ...] | None:
            txn.execute(
                "SELECT user_id,device_id,expires_ts,code_challenge,native_ready FROM agentim_initial_accounts WHERE attempt_id=?",
                (attempt_id,),
            )
            return txn.fetchone()

        return await self.pool.runInteraction("agentim_initial_binding", read)

    @staticmethod
    def require_binding(
        row: tuple[Any, ...],
        user_id: str,
        device_id: str,
        expires_ts: int,
        code_challenge: str,
    ) -> None:
        if row[:4] != (user_id, device_id, expires_ts, code_challenge):
            raise SynapseError(409, "Registration binding conflicts", Codes.FORBIDDEN)

    async def create(
        self,
        attempt_id: str,
        user_id: str,
        device_id: str,
        expires_ts: int,
        code_challenge: str,
        display_name: str,
    ) -> None:
        def create(txn: "LoggingTransaction") -> None:
            # Lock an attempt even before its binding exists. All workers share
            # this transaction lock; a different attempt cannot claim a native ID.
            if isinstance(self.native.database_engine, PostgresEngine):
                key = int.from_bytes(
                    hashlib.sha256(attempt_id.encode()).digest()[:8], "big", signed=True
                )
                txn.execute("SELECT pg_advisory_xact_lock(?)", (key,))
            txn.execute(
                "SELECT user_id,device_id,expires_ts,code_challenge,native_ready FROM agentim_initial_accounts WHERE attempt_id=?",
                (attempt_id,),
            )
            row = txn.fetchone()
            if row:
                self.require_binding(
                    row, user_id, device_id, expires_ts, code_challenge
                )
                return
            # Reuse the native account/profile/stats/cache-invalidation writer;
            # never duplicate INSERTs into users in an external extension module.
            self.native._register_user(
                txn,
                user_id,
                None,
                False,
                False,
                None,
                display_name,
                False,
                self.hs.config.user_types.default_user_type,
                False,
                False,
            )
            txn.execute(
                "INSERT INTO agentim_initial_accounts(attempt_id,user_id,device_id,expires_ts,code_challenge) VALUES (?,?,?,?,?)",
                (attempt_id, user_id, device_id, expires_ts, code_challenge),
            )

        await self.pool.runInteraction("agentim_initial_create", create)

    def _locked(self, txn: "LoggingTransaction", attempt_id: str) -> tuple[Any, ...]:
        lock = (
            " FOR UPDATE"
            if isinstance(self.native.database_engine, PostgresEngine)
            else ""
        )
        txn.execute(
            "SELECT user_id,device_id,expires_ts,completed,grant_expires_ts,native_ready FROM agentim_initial_accounts WHERE attempt_id=?"
            + lock,
            (attempt_id,),
        )
        row = txn.fetchone()
        if not row:
            raise SynapseError(
                409, "Initial identity not provisioned", "M_REGISTRATION_INCOMPLETE"
            )
        return row

    async def issue(self, attempt_id: str, token: str, now: int, lifetime: int) -> int:
        def issue(txn: "LoggingTransaction") -> int:
            row = self._locked(txn, attempt_id)
            if row[3] or row[2] <= now or not row[5]:
                raise SynapseError(
                    409, "Initial authorization ended", "M_REGISTRATION_ENDED"
                )
            if row[4] and row[4] > now:
                raise SynapseError(
                    429,
                    "Wait before retrying initial login",
                    Codes.LIMIT_EXCEEDED,
                    additional_fields={"retry_after_ms": row[4] - now},
                )
            txn.execute(
                "UPDATE agentim_initial_accounts SET grant_hash=?,grant_expires_ts=?,grant_used=FALSE WHERE attempt_id=?",
                (digest(token), min(now + lifetime, row[2]), attempt_id),
            )

            return min(lifetime, row[2] - now)

        return await self.pool.runInteraction("agentim_initial_issue", issue)

    async def consume(self, token: str, device_id: object) -> LoginTokenLookupResult:
        now = self.hs.get_clock().time_msec()

        def consume(txn: "LoggingTransaction") -> LoginTokenLookupResult:
            lock = (
                " FOR UPDATE"
                if isinstance(self.native.database_engine, PostgresEngine)
                else ""
            )
            txn.execute(
                "SELECT attempt_id,user_id,device_id,expires_ts,completed,grant_expires_ts,grant_used,native_ready FROM agentim_initial_accounts WHERE grant_hash=?"
                + lock,
                (digest(token),),
            )
            row = txn.fetchone()
            if (
                not row
                or row[4]
                or row[3] <= now
                or row[5] <= now
                or row[6]
                or row[2] != device_id
                or not row[7]
            ):
                raise LoginError(
                    403, "Invalid initial device authorization", Codes.FORBIDDEN
                )
            txn.execute(
                "UPDATE agentim_initial_accounts SET grant_used=TRUE WHERE attempt_id=?",
                (row[0],),
            )
            return LoginTokenLookupResult(row[1], "agentim.initial", row[0])

        return await self.pool.runInteraction("agentim_initial_consume", consume)

    async def mark_ready(self, attempt_id: str) -> None:
        await self.pool.simple_update_one(
            "agentim_initial_accounts",
            {"attempt_id": attempt_id},
            {"native_ready": True},
        )

    async def complete(self, attempt_id: str, user_id: str, device_id: str) -> None:
        def complete(txn: "LoggingTransaction") -> None:
            row = self._locked(txn, attempt_id)
            if row[:2] != (user_id, device_id):
                raise SynapseError(
                    403, "Wrong initial identity/device", Codes.FORBIDDEN
                )
            txn.execute(
                "UPDATE agentim_initial_accounts SET completed=TRUE,grant_hash=NULL WHERE attempt_id=?",
                (attempt_id,),
            )

        await self.pool.runInteraction("agentim_initial_complete", complete)
