#
# This file is licensed under the Affero General Public License (AGPL) version 3.
#
# Copyright 2014-2021 The Matrix.org Foundation C.I.C.
# Copyright (C) 2023 New Vector, Ltd
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# See the GNU Affero General Public License for more details:
# <https://www.gnu.org/licenses/agpl-3.0.html>.
#
# Originally licensed under the Apache License, Version 2.0:
# <http://www.apache.org/licenses/LICENSE-2.0>.
#
# [This file includes modifications made by New Vector Limited]
#
#
import logging
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
)

from synapse.api.constants import ApprovalNoticeMedium
from synapse.api.errors import (
    Codes,
    InvalidClientTokenError,
    LoginError,
    NotApprovedError,
    SynapseError,
)
from synapse.api.ratelimiting import Ratelimiter
from synapse.appservice import ApplicationService
from synapse.http.server import HttpServer
from synapse.http.servlet import (
    RestServlet,
    parse_json_object_from_request,
)
from synapse.http.site import RequestInfo, SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.rest.well_known import WellKnownBuilder
from synapse.types import JsonDict, UserID

if TYPE_CHECKING:
    from synapse.server import HomeServer

from synapse.rest.client.login_completion import (
    LoginResponse,
    complete_login,
    jwt_login,
    token_login,
)
from synapse.rest.client.login_refresh import RefreshTokenServlet
from synapse.rest.client.login_sso import (
    CasTicketServlet,
    SsoRedirectServlet,
    _get_auth_flow_dict_for_idp,
    _load_sso_handlers,
)

logger = logging.getLogger(__name__)


class LoginRestServlet(RestServlet):
    PATTERNS = client_patterns("/login$", v1=True)
    CATEGORY = "Registration/login requests"

    CAS_TYPE = "m.login.cas"
    SSO_TYPE = "m.login.sso"
    TOKEN_TYPE = "m.login.token"
    JWT_TYPE = "org.matrix.login.jwt"
    APPSERVICE_TYPE = "m.login.application_service"
    REFRESH_TOKEN_PARAM = "refresh_token"

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self._main_store = hs.get_datastores().main

        # JWT configuration variables.
        self.jwt_enabled = hs.config.jwt.jwt_enabled

        # SSO configuration.
        self.saml2_enabled = hs.config.saml2.saml2_enabled
        self.cas_enabled = hs.config.cas.cas_enabled
        self.oidc_enabled = hs.config.oidc.oidc_enabled
        self._refresh_tokens_enabled = (
            hs.config.registration.refreshable_access_token_lifetime is not None
        )

        # Whether we need to check if the user has been approved or not.
        self._require_approval = (
            hs.config.experimental.msc3866.enabled
            and hs.config.experimental.msc3866.require_approval_for_new_accounts
        )

        # Whether get login token is enabled.
        self._get_login_token_enabled = hs.config.auth.login_via_existing_enabled

        self.auth = hs.get_auth()

        self.clock = hs.get_clock()

        self.auth_handler = self.hs.get_auth_handler()
        self.registration_handler = hs.get_registration_handler()
        self._sso_handler = hs.get_sso_handler()
        self._spam_checker = hs.get_module_api_callbacks().spam_checker
        self._account_validity_handler = hs.get_account_validity_handler()

        self._well_known_builder = WellKnownBuilder(hs)
        self._address_ratelimiter = Ratelimiter(
            store=self._main_store,
            clock=hs.get_clock(),
            cfg=self.hs.config.ratelimiting.rc_login_address,
        )
        self._account_ratelimiter = Ratelimiter(
            store=self._main_store,
            clock=hs.get_clock(),
            cfg=self.hs.config.ratelimiting.rc_login_account,
        )

        # ensure the CAS/SAML/OIDC handlers are loaded on this worker instance.
        # The reason for this is to ensure that the auth_provider_ids are registered
        # with SsoHandler, which in turn ensures that the login/registration prometheus
        # counters are initialised for the auth_provider_ids.
        _load_sso_handlers(hs)

    def on_GET(self, request: SynapseRequest) -> tuple[int, JsonDict]:
        flows: list[JsonDict] = []
        if self.jwt_enabled:
            flows.append({"type": LoginRestServlet.JWT_TYPE})

        if self.cas_enabled:
            # we advertise CAS for backwards compat, though MSC1721 renamed it
            # to SSO.
            flows.append({"type": LoginRestServlet.CAS_TYPE})

        # The login token flow requires m.login.token to be advertised.
        support_login_token_flow = self._get_login_token_enabled

        if self.cas_enabled or self.saml2_enabled or self.oidc_enabled:
            flows.append(
                {
                    "type": LoginRestServlet.SSO_TYPE,
                    "identity_providers": [
                        _get_auth_flow_dict_for_idp(idp)
                        for idp in self._sso_handler.get_identity_providers().values()
                    ],
                }
            )

            # SSO requires a login token to be generated, so we need to advertise that flow
            support_login_token_flow = True

        # While it's valid for us to advertise this login type generally,
        # synapse currently only gives out these tokens as part of the
        # SSO login flow or as part of login via an existing session.
        #
        # Generally we don't want to advertise login flows that clients
        # don't know how to implement, since they (currently) will always
        # fall back to the fallback API if they don't understand one of the
        # login flow types returned.
        if support_login_token_flow:
            tokenTypeFlow: dict[str, Any] = {"type": LoginRestServlet.TOKEN_TYPE}
            # If the login token flow is enabled advertise the get_login_token flag.
            if self._get_login_token_enabled:
                tokenTypeFlow["get_login_token"] = True
            flows.append(tokenTypeFlow)

        flows.extend({"type": t} for t in self.auth_handler.get_supported_login_types())

        flows.append({"type": LoginRestServlet.APPSERVICE_TYPE})

        return 200, {"flows": flows}

    async def on_POST(self, request: SynapseRequest) -> tuple[int, LoginResponse]:
        login_submission = parse_json_object_from_request(request)

        # Check to see if the client requested a refresh token.
        client_requested_refresh_token = login_submission.get(
            LoginRestServlet.REFRESH_TOKEN_PARAM, False
        )
        if not isinstance(client_requested_refresh_token, bool):
            raise SynapseError(400, "`refresh_token` should be true or false.")

        should_issue_refresh_token = (
            self._refresh_tokens_enabled and client_requested_refresh_token
        )

        request_info = request.request_info()

        try:
            if login_submission["type"] == LoginRestServlet.APPSERVICE_TYPE:
                requester = await self.auth.get_user_by_req(request)
                appservice = (
                    self._main_store.get_app_service_by_id(requester.app_service_id)
                    if requester.app_service_id
                    else None
                )

                if appservice is None:
                    raise InvalidClientTokenError(
                        "This login method is only valid for application services"
                    )

                if appservice.msc4190_device_management:
                    raise SynapseError(
                        400,
                        "This appservice has MSC4190 enabled, so appservice login cannot be used.",
                        errcode=Codes.APPSERVICE_LOGIN_UNSUPPORTED,
                    )

                if appservice.is_rate_limited():
                    await self._address_ratelimiter.ratelimit(
                        None, request.getClientAddress().host
                    )

                result = await self._do_appservice_login(
                    login_submission,
                    appservice,
                    should_issue_refresh_token=should_issue_refresh_token,
                    request_info=request_info,
                )
            elif (
                self.jwt_enabled
                and login_submission["type"] == LoginRestServlet.JWT_TYPE
            ):
                await self._address_ratelimiter.ratelimit(
                    None, request.getClientAddress().host
                )
                result = await self._do_jwt_login(
                    login_submission,
                    should_issue_refresh_token=should_issue_refresh_token,
                    request_info=request_info,
                )
            elif login_submission["type"] == LoginRestServlet.TOKEN_TYPE:
                await self._address_ratelimiter.ratelimit(
                    None, request.getClientAddress().host
                )
                result = await self._do_token_login(
                    login_submission,
                    should_issue_refresh_token=should_issue_refresh_token,
                    request_info=request_info,
                )
            else:
                await self._address_ratelimiter.ratelimit(
                    None, request.getClientAddress().host
                )
                result = await self._do_other_login(
                    login_submission,
                    should_issue_refresh_token=should_issue_refresh_token,
                    request_info=request_info,
                )
        except KeyError:
            raise SynapseError(400, "Missing JSON keys.")

        if self._require_approval:
            approved = await self.auth_handler.is_user_approved(result["user_id"])
            if not approved:
                raise NotApprovedError(
                    msg="This account is pending approval by a server administrator.",
                    approval_notice_medium=ApprovalNoticeMedium.NONE,
                )

        well_known_data = await self._well_known_builder.get_well_known()
        if well_known_data:
            result["well_known"] = well_known_data
        return 200, result

    async def _do_appservice_login(
        self,
        login_submission: JsonDict,
        appservice: ApplicationService,
        should_issue_refresh_token: bool = False,
        *,
        request_info: RequestInfo,
    ) -> LoginResponse:
        identifier = login_submission.get("identifier")
        logger.info("Got appservice login request with identifier: %r", identifier)

        if not isinstance(identifier, dict):
            raise SynapseError(
                400, "Invalid identifier in login submission", Codes.INVALID_PARAM
            )

        # this login flow only supports identifiers of type "m.id.user".
        if identifier.get("type") != "m.id.user":
            raise SynapseError(
                400, "Unknown login identifier type", Codes.INVALID_PARAM
            )

        user = identifier.get("user")
        if not isinstance(user, str):
            raise SynapseError(400, "Invalid user in identifier", Codes.INVALID_PARAM)

        if user.startswith("@"):
            qualified_user_id = user
        else:
            qualified_user_id = UserID(user, self.hs.hostname).to_string()

        if not appservice.is_interested_in_user(qualified_user_id):
            raise LoginError(403, "Invalid access_token", errcode=Codes.FORBIDDEN)

        return await self._complete_login(
            qualified_user_id,
            login_submission,
            ratelimit=appservice.is_rate_limited(),
            should_issue_refresh_token=should_issue_refresh_token,
            # The user represented by an appservice's configured sender_localpart
            # is not actually created in Synapse.
            should_check_deactivated_or_locked=(
                qualified_user_id != appservice.sender.to_string()
            ),
            request_info=request_info,
        )

    async def _do_other_login(
        self,
        login_submission: JsonDict,
        should_issue_refresh_token: bool = False,
        *,
        request_info: RequestInfo,
    ) -> LoginResponse:
        """Handle non-token/saml/jwt logins

        Args:
            login_submission:
            should_issue_refresh_token: True if this login should issue
                a refresh token alongside the access token.

        Returns:
            HTTP response
        """
        # Log the request we got, but only certain fields to minimise the chance of
        # logging someone's password (even if they accidentally put it in the wrong
        # field)
        logger.info(
            "Got login request with identifier: %r, medium: %r, address: %r, user: %r",
            login_submission.get("identifier"),
            login_submission.get("medium"),
            login_submission.get("address"),
            login_submission.get("user"),
        )
        canonical_user_id, callback = await self.auth_handler.validate_login(
            login_submission, ratelimit=True
        )
        result = await self._complete_login(
            canonical_user_id,
            login_submission,
            callback,
            should_issue_refresh_token=should_issue_refresh_token,
            request_info=request_info,
        )
        return result

    async def _complete_login(
        self,
        user_id: str,
        login_submission: JsonDict,
        callback: Callable[[LoginResponse], Awaitable[None]] | None = None,
        create_non_existent_users: bool = False,
        default_display_name: str | None = None,
        ratelimit: bool = True,
        auth_provider_id: str | None = None,
        should_issue_refresh_token: bool = False,
        auth_provider_session_id: str | None = None,
        should_check_deactivated_or_locked: bool = True,
        *,
        request_info: RequestInfo,
    ) -> LoginResponse:
        return await complete_login(
            self,
            user_id=user_id,
            login_submission=login_submission,
            callback=callback,
            create_non_existent_users=create_non_existent_users,
            default_display_name=default_display_name,
            ratelimit=ratelimit,
            auth_provider_id=auth_provider_id,
            should_issue_refresh_token=should_issue_refresh_token,
            auth_provider_session_id=auth_provider_session_id,
            should_check_deactivated_or_locked=should_check_deactivated_or_locked,
            request_info=request_info,
        )

    async def _do_token_login(
        self,
        login_submission: JsonDict,
        should_issue_refresh_token: bool = False,
        *,
        request_info: RequestInfo,
    ) -> LoginResponse:
        return await token_login(
            self,
            login_submission=login_submission,
            should_issue_refresh_token=should_issue_refresh_token,
            request_info=request_info,
        )

    async def _do_jwt_login(
        self,
        login_submission: JsonDict,
        should_issue_refresh_token: bool = False,
        *,
        request_info: RequestInfo,
    ) -> LoginResponse:
        return await jwt_login(
            self,
            login_submission=login_submission,
            should_issue_refresh_token=should_issue_refresh_token,
            request_info=request_info,
        )


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    if hs.config.mas.enabled:
        return

    LoginRestServlet(hs).register(http_server)
    if (
        hs.config.worker.worker_app is None
        and hs.config.registration.refreshable_access_token_lifetime is not None
    ):
        RefreshTokenServlet(hs).register(http_server)
    if (
        hs.config.cas.cas_enabled
        or hs.config.saml2.saml2_enabled
        or hs.config.oidc.oidc_enabled
    ):
        SsoRedirectServlet(hs).register(http_server)
    if hs.config.cas.cas_enabled:
        CasTicketServlet(hs).register(http_server)
