# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 AgentIM contributors
"""Native registration checks and account lifecycle for first Agent devices."""

import secrets
from typing import TYPE_CHECKING

from synapse.api.errors import Codes, SynapseError
from synapse.config._base import ConfigError
from synapse.spam_checker_api import RegistrationBehaviour
from synapse.storage.databases.main.agent_registration import InitialAccountStore
from synapse.types import UserID

if TYPE_CHECKING:
    from synapse.server import HomeServer

TOKEN_PREFIX = "agentim_initial_"
GRANT_LIFETIME_MS = 60_000


class InitialRegistration:
    def __init__(self, hs: "HomeServer") -> None:
        self.hs = hs
        self.store = InitialAccountStore(hs)

    def check_open_policy(self) -> None:
        config = self.hs.config
        registration = config.registration
        if (
            config.mas.enabled
            or registration.registrations_require_3pid
            or registration.registration_requires_token
            or config.captcha.enable_registration_captcha
            or config.consent.user_consent_at_registration
            or (
                config.experimental.msc3866.enabled
                and config.experimental.msc3866.require_approval_for_new_accounts
            )
        ):
            raise ConfigError("AgentIM open registration conflicts with native policy")
        if config.worker.worker_app is not None:
            raise ConfigError("AgentIM initial registration requires the main process")

    async def provision(
        self,
        attempt_id: str,
        localpart: str,
        device_id: str,
        expires_ts: int,
        code_challenge: str,
        display_name: str | None,
        address: str,
    ) -> str:
        user = UserID(localpart, self.hs.hostname)
        existing = await self.store.binding(attempt_id)
        if existing:
            self.store.require_binding(
                existing, user.to_string(), device_id, expires_ts, code_challenge
            )
            await self._finish_provision(attempt_id, user)
            return user.to_string()
        handler = self.hs.get_registration_handler()
        await handler.check_registration_ratelimit(address)
        spam = await self.hs.get_module_api_callbacks().spam_checker.check_registration_for_spam(
            None, localpart, [], auth_provider_id="agentim.initial"
        )
        if spam != RegistrationBehaviour.ALLOW:
            raise SynapseError(
                403, "Registration denied by native policy", Codes.FORBIDDEN
            )
        await self.hs.get_auth_blocking().check_auth_blocking()
        try:
            await handler.check_username(localpart)
            await self.store.create(
                attempt_id,
                user.to_string(),
                device_id,
                expires_ts,
                code_challenge,
                display_name or localpart,
            )
        except SynapseError:
            # Another worker may have committed this exact native binding after
            # our initial lookup. A fresh transaction proves ownership; name
            # availability or a generic integrity error never does.
            concurrent = await self.store.binding(attempt_id)
            if concurrent is None:
                raise
            self.store.require_binding(
                concurrent, user.to_string(), device_id, expires_ts, code_challenge
            )
            await self._finish_provision(attempt_id, user)
            return user.to_string()
        await self._finish_provision(attempt_id, user)
        return user.to_string()

    async def _finish_provision(self, attempt_id: str, user: UserID) -> None:
        binding = await self.store.binding(attempt_id)
        if binding and binding[4]:
            return
        # Native account state is already durable. These native follow-up operations
        # do not grant account control; a retry uses the persisted binding above.
        await self.hs.get_account_validity_handler().on_user_registration(
            user.to_string()
        )
        profile = await self.hs.get_datastores().main.get_profileinfo(user)
        await self.hs.get_user_directory_handler().handle_local_profile_change(
            user.to_string(), profile
        )
        await self.hs.get_registration_handler()._auto_join_rooms(user.to_string())
        await self.store.mark_ready(attempt_id)

    async def issue(self, attempt_id: str) -> tuple[str, int]:
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        now = self.hs.get_clock().time_msec()
        lifetime = await self.store.issue(attempt_id, token, now, GRANT_LIFETIME_MS)
        return token, lifetime

    async def complete(self, attempt_id: str, user_id: str, device_id: str) -> None:
        await self.store.complete(attempt_id, user_id, device_id)
