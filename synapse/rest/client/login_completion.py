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
    TypedDict,
)

from synapse.api.errors import (
    Codes,
    LoginError,
    SynapseError,
    UserDeactivatedError,
    UserLockedError,
)
from synapse.http.site import RequestInfo
from synapse.types import JsonDict, UserID

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


if TYPE_CHECKING:
    from synapse.rest.client.login import LoginRestServlet


class LoginResponse(TypedDict, total=False):
    user_id: str
    access_token: str | None
    home_server: str
    expires_in_ms: int | None
    refresh_token: str | None
    device_id: str | None
    well_known: dict[str, Any] | None


async def complete_login(
    servlet: "LoginRestServlet",
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
    """Called when we've successfully authed the user and now need to
    actually login them in (e.g. create devices). This gets called on
    all successful logins.

    Applies the ratelimiting for successful login attempts against an
    account.

    Args:
        user_id: ID of the user to register.
        login_submission: Dictionary of login information.
        callback: Callback function to run after login.
        create_non_existent_users: Whether to create the user if they don't
            exist. Defaults to False.
        ratelimit: Whether to ratelimit the login request.
        auth_provider_id: The SSO IdP the user used, if any.
        should_issue_refresh_token: True if this login should issue
            a refresh token alongside the access token.
        auth_provider_session_id: The session ID got during login from the SSO IdP.
        should_check_deactivated_or_locked: True if the user should be checked for
            deactivation or locked status before logging in.

            This exists purely for appservice's configured sender_localpart
            which doesn't have an associated user in the database.
        request_info: The user agent/IP address of the user.

    Returns:
        Dictionary of account information after successful login.
    """

    # Before we actually log them in we check if they've already logged in
    # too often. This happens here rather than before as we don't
    # necessarily know the user before now.
    if ratelimit:
        await servlet._account_ratelimiter.ratelimit(None, user_id.lower())

    if create_non_existent_users:
        canonical_uid = await servlet.auth_handler.check_user_exists(user_id)
        if not canonical_uid:
            canonical_uid = await servlet.registration_handler.register_user(
                localpart=UserID.from_string(user_id).localpart,
                default_display_name=default_display_name,
            )
        user_id = canonical_uid

    # If the account has been deactivated or locked, do not proceed with the login.
    if should_check_deactivated_or_locked:
        deactivated = await servlet._main_store.get_user_deactivated_status(user_id)
        if deactivated:
            raise UserDeactivatedError("This account has been deactivated")
        locked = await servlet._main_store.get_user_locked_status(user_id)
        if locked:
            raise UserLockedError()

    device_id = login_submission.get("device_id")

    # If device_id is present, check that device_id is not longer than a reasonable 512 characters
    if device_id and len(device_id) > 512:
        raise LoginError(
            400,
            "device_id cannot be longer than 512 characters.",
            errcode=Codes.INVALID_PARAM,
        )

    if servlet._require_approval:
        approved = await servlet.auth_handler.is_user_approved(user_id)
        if not approved:
            # If the user isn't approved (and needs to be) we won't allow them to
            # actually log in, so we don't want to create a device/access token.
            return LoginResponse(
                user_id=user_id,
                home_server=servlet.hs.hostname,
            )

    initial_display_name = login_submission.get("initial_device_display_name")
    spam_check = await servlet._spam_checker.check_login_for_spam(
        user_id,
        device_id=device_id,
        initial_display_name=initial_display_name,
        request_info=[(request_info.user_agent, request_info.ip)],
        auth_provider_id=auth_provider_id,
    )
    if spam_check != servlet._spam_checker.NOT_SPAM:
        logger.info("Blocking login due to spam checker")
        raise SynapseError(
            403,
            msg="Login was blocked by the server",
            errcode=spam_check[0],
            additional_fields=spam_check[1],
        )

    (
        device_id,
        access_token,
        valid_until_ms,
        refresh_token,
    ) = await servlet.registration_handler.register_device(
        user_id,
        device_id,
        initial_display_name,
        auth_provider_id=auth_provider_id,
        should_issue_refresh_token=should_issue_refresh_token,
        auth_provider_session_id=auth_provider_session_id,
    )

    result = LoginResponse(
        user_id=user_id,
        access_token=access_token,
        home_server=servlet.hs.hostname,
        device_id=device_id,
    )

    # execute the callback
    await servlet._account_validity_handler.on_user_login(
        user_id,
        auth_provider_type=login_submission.get("type"),
        auth_provider_id=auth_provider_id,
    )

    if valid_until_ms is not None:
        expires_in_ms = valid_until_ms - servlet.clock.time_msec()
        result["expires_in_ms"] = expires_in_ms

    if refresh_token is not None:
        result["refresh_token"] = refresh_token

    if callback is not None:
        await callback(result)

    return result


async def token_login(
    servlet: "LoginRestServlet",
    login_submission: JsonDict,
    should_issue_refresh_token: bool = False,
    *,
    request_info: RequestInfo,
) -> LoginResponse:
    """
    Handle token login.

    Args:
        login_submission: The JSON request body.
        should_issue_refresh_token: True if this login should issue
            a refresh token alongside the access token.

    Returns:
        The body of the JSON response.
    """
    token = login_submission["token"]
    from synapse.handlers.agent_registration import TOKEN_PREFIX
    from synapse.storage.databases.main.agent_registration import InitialAccountStore

    if isinstance(token, str) and token.startswith(TOKEN_PREFIX):
        res = await InitialAccountStore(servlet.hs).consume(
            token, login_submission.get("device_id")
        )
    else:
        res = await servlet.auth_handler.consume_login_token(token)

    return await servlet._complete_login(
        res.user_id,
        login_submission,
        servlet.auth_handler._sso_login_callback,
        auth_provider_id=res.auth_provider_id,
        should_issue_refresh_token=should_issue_refresh_token,
        auth_provider_session_id=res.auth_provider_session_id,
        request_info=request_info,
    )


async def jwt_login(
    servlet: "LoginRestServlet",
    login_submission: JsonDict,
    should_issue_refresh_token: bool = False,
    *,
    request_info: RequestInfo,
) -> LoginResponse:
    """
    Handle the custom JWT login.

    Args:
        login_submission: The JSON request body.
        should_issue_refresh_token: True if this login should issue
            a refresh token alongside the access token.

    Returns:
        The body of the JSON response.
    """
    user_id, default_display_name = servlet.hs.get_jwt_handler().validate_login(
        login_submission
    )
    return await servlet._complete_login(
        user_id,
        login_submission,
        create_non_existent_users=True,
        default_display_name=default_display_name,
        should_issue_refresh_token=should_issue_refresh_token,
        request_info=request_info,
    )
