# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 AgentIM contributors
"""Public companion API for native, recoverable initial Agent registration.

Only this Fork-owned boundary accesses homeserver internals. External modules
pass their ModuleApi and never write native account/device tables themselves.
"""

from typing import TYPE_CHECKING

from synapse.handlers.agent_registration import InitialRegistration

if TYPE_CHECKING:
    from synapse.module_api import ModuleApi


class AgentRegistrationApi:
    def __init__(self, api: "ModuleApi") -> None:
        self._registration = InitialRegistration(api._hs)

    def check_open_policy(self) -> None:
        """Reject native settings which require interactive or human approval."""
        self._registration.check_open_policy()

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
        """Atomically create a native account and bind it to this attempt."""
        return await self._registration.provision(
            attempt_id,
            localpart,
            device_id,
            expires_ts,
            code_challenge,
            display_name,
            address,
        )

    async def issue(self, attempt_id: str) -> tuple[str, int]:
        """Issue one short-lived, first-device-bound m.login.token grant."""
        return await self._registration.issue(attempt_id)

    async def complete(self, attempt_id: str, user_id: str, device_id: str) -> None:
        """End bootstrap authority after authenticated first-device confirmation."""
        await self._registration.complete(attempt_id, user_id, device_id)
