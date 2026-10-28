# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 AgentIM contributors
"""Native transaction and standard login tests for first Agent devices."""

from unittest.mock import patch

from synapse.api.errors import SynapseError
from synapse.module_api.agent_registration import AgentRegistrationApi
from synapse.rest.client import login
from synapse.storage.databases.main.agent_registration import InitialAccountStore

from tests import unittest


class InitialRegistrationTestCase(unittest.HomeserverTestCase):
    servlets = [login.register_servlets]

    def prepare(self, reactor, clock, hs):
        self.api = AgentRegistrationApi(hs.get_module_api())
        self.store = InitialAccountStore(hs)
        self.attempt = "A" * 43
        self.device = "B" * 43
        self.challenge = "C" * 43
        self.expires = clock.time_msec() + 86_400_000

    def provision(self, attempt=None, localpart="native-agent"):
        return self.api.provision(
            attempt or self.attempt,
            localpart,
            self.device,
            self.expires,
            self.challenge,
            "Native agent",
            "127.0.0.1",
        )

    def test_account_and_attempt_are_atomic_and_retries_preserve_identity(self):
        user = self.get_success(self.provision())
        self.assertEqual(self.get_success(self.provision()), user)
        row = self.get_success(self.store.binding(self.attempt))
        self.assertEqual(row, (user, self.device, self.expires, self.challenge, True))
        self.get_failure(self.provision("D" * 43), SynapseError)
        self.assertEqual(
            self.get_success(
                self.hs.get_datastores().main.get_user_by_id(user)
            ).user_id.to_string(),
            user,
        )

    def test_failure_after_native_insert_rolls_back_binding_and_account(self):
        native = self.hs.get_datastores().main
        original = native._register_user

        def crash(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError("synthetic transaction fault")

        with patch.object(native, "_register_user", crash):
            self.get_failure(self.provision(), RuntimeError)
        self.assertIsNone(self.get_success(self.store.binding(self.attempt)))
        self.assertIsNone(self.get_success(native.get_user_by_id("@native-agent:test")))
        self.assertEqual(self.get_success(self.provision()), "@native-agent:test")

    def test_different_proof_or_first_device_cannot_resume(self):
        self.get_success(self.provision())
        self.get_failure(
            self.api.provision(
                self.attempt,
                "native-agent",
                "D" * 43,
                self.expires,
                self.challenge,
                None,
                "127.0.0.1",
            ),
            SynapseError,
        )

    def test_native_followup_failure_can_resume_without_recreating_user(self):
        handler = self.hs.get_account_validity_handler()
        with patch.object(
            handler,
            "on_user_registration",
            side_effect=RuntimeError("synthetic callback failure"),
        ):
            self.get_failure(self.provision(), RuntimeError)
        self.assertFalse(self.get_success(self.store.binding(self.attempt))[4])
        self.assertEqual(self.get_success(self.provision()), "@native-agent:test")
        self.assertTrue(self.get_success(self.store.binding(self.attempt))[4])
        self.get_failure(
            self.api.provision(
                self.attempt,
                "native-agent",
                self.device,
                self.expires,
                "E" * 43,
                None,
                "127.0.0.1",
            ),
            SynapseError,
        )

    def test_standard_token_login_is_bound_to_first_device_and_single_use(self):
        self.get_success(self.provision())
        token, lifetime = self.get_success(self.api.issue(self.attempt))
        self.assertEqual(lifetime, 60_000)
        wrong = self.make_request(
            "POST",
            "/login",
            {
                "type": "m.login.token",
                "token": token,
                "device_id": "WRONG",
            },
        )
        self.assertEqual(wrong.code, 403)
        right = self.make_request(
            "POST",
            "/login",
            {
                "type": "m.login.token",
                "token": token,
                "device_id": self.device,
            },
        )
        self.assertEqual(right.code, 200, right.json_body)
        self.assertEqual(right.json_body["device_id"], self.device)
        self.assertEqual(right.json_body["user_id"], "@native-agent:test")
        replay = self.make_request(
            "POST",
            "/login",
            {
                "type": "m.login.token",
                "token": token,
                "device_id": self.device,
            },
        )
        self.assertEqual(replay.code, 403)

    def test_expiry_reissue_completion_and_no_plaintext_grants(self):
        user = self.get_success(self.provision())
        token, _ = self.get_success(self.api.issue(self.attempt))
        self.get_failure(self.api.issue(self.attempt), SynapseError)
        self.reactor.advance(61)
        self.get_failure(self.store.consume(token, self.device), SynapseError)
        replacement, _ = self.get_success(self.api.issue(self.attempt))
        stored = self.get_success(
            self.hs.get_datastores().main.db_pool.simple_select_one_onecol(
                "agentim_initial_accounts", {"attempt_id": self.attempt}, "grant_hash"
            )
        )
        self.assertEqual(len(stored), 64)
        self.assertNotEqual(stored, replacement)
        self.assertNotEqual(token, replacement)
        self.get_failure(self.api.complete(self.attempt, user, "WRONG"), SynapseError)
        self.get_success(self.api.complete(self.attempt, user, self.device))
        self.get_success(self.api.complete(self.attempt, user, self.device))
        self.get_failure(self.store.consume(replacement, self.device), SynapseError)
        self.get_failure(self.api.issue(self.attempt), SynapseError)
