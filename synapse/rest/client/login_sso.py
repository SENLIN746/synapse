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
import re
from typing import (
    TYPE_CHECKING,
)

from synapse.api.errors import (
    Codes,
    SynapseError,
)
from synapse.api.urls import CLIENT_API_PREFIX
from synapse.handlers.sso import SsoIdentityProvider, SsoSetupError
from synapse.http import get_request_uri
from synapse.http.server import finish_request
from synapse.http.servlet import (
    RestServlet,
    parse_bytes_from_args,
    parse_string,
)
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


def _get_auth_flow_dict_for_idp(idp: SsoIdentityProvider) -> JsonDict:
    """Return an entry for the login flow dict

    Returns an entry suitable for inclusion in "identity_providers" in the
    response to GET /_matrix/client/r0/login

    Args:
        idp: the identity provider to describe
    """
    e: JsonDict = {"id": idp.idp_id, "name": idp.idp_name}
    if idp.idp_icon:
        e["icon"] = idp.idp_icon
    if idp.idp_brand:
        e["brand"] = idp.idp_brand
    return e


class SsoRedirectServlet(RestServlet):
    PATTERNS = list(client_patterns("/login/(cas|sso)/redirect$", v1=True)) + [
        re.compile(
            "^"
            + CLIENT_API_PREFIX
            + "/(r0|v3)/login/sso/redirect/(?P<idp_id>[A-Za-z0-9_.~-]+)$"
        )
    ]
    CATEGORY = "SSO requests needed for all SSO providers"

    def __init__(self, hs: "HomeServer"):
        # make sure that the relevant handlers are instantiated, so that they
        # register themselves with the main SSOHandler.
        _load_sso_handlers(hs)
        self._sso_handler = hs.get_sso_handler()
        self._public_baseurl = hs.config.server.public_baseurl

    async def on_GET(self, request: SynapseRequest, idp_id: str | None = None) -> None:
        if not self._public_baseurl:
            raise SynapseError(400, "SSO requires a valid public_baseurl")

        # if this isn't the expected hostname, redirect to the right one, so that we
        # get our cookies back.
        requested_uri = get_request_uri(request)
        baseurl_bytes = self._public_baseurl.encode("utf-8")
        if not requested_uri.startswith(baseurl_bytes):
            # swap out the incorrect base URL for the right one.
            #
            # The idea here is to redirect from
            #    https://foo.bar/whatever/_matrix/...
            # to
            #    https://public.baseurl/_matrix/...
            #
            i = requested_uri.index(b"/_matrix")
            new_uri = baseurl_bytes[:-1] + requested_uri[i:]
            logger.info(
                "Requested URI %s is not canonical: redirecting to %s",
                requested_uri.decode("utf-8", errors="replace"),
                new_uri.decode("utf-8", errors="replace"),
            )
            request.redirect(new_uri)
            finish_request(request)
            return

        args: dict[bytes, list[bytes]] = request.args  # type: ignore
        client_redirect_url = parse_bytes_from_args(args, "redirectUrl", required=True)
        try:
            sso_url = await self._sso_handler.handle_redirect_request(
                request,
                client_redirect_url,
                idp_id,
            )
        except SsoSetupError:
            logger.exception(
                "Login redirect failed because SSO/identity provider %r unavailable",
                idp_id,
            )
            # Show an error page that is slightly more friendly than JSON
            self._sso_handler.render_error(
                request,
                "provider_unavailable",
                "This login provider is currently unavailable on this homeserver.",
                code=503,
            )
            return

        logger.info("Redirecting to %s", sso_url)
        request.redirect(sso_url)
        finish_request(request)


class CasTicketServlet(RestServlet):
    PATTERNS = client_patterns("/login/cas/ticket$", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self._cas_handler = hs.get_cas_handler()

    async def on_GET(self, request: SynapseRequest) -> None:
        client_redirect_url = parse_string(request, "redirectUrl")
        ticket = parse_string(request, "ticket", required=True)

        # Maybe get a session ID (if this ticket is from user interactive
        # authentication).
        session = parse_string(request, "session")

        # Either client_redirect_url or session must be provided.
        if not client_redirect_url and not session:
            message = "Missing string query parameter redirectUrl or session"
            raise SynapseError(400, message, errcode=Codes.MISSING_PARAM)

        await self._cas_handler.handle_ticket(
            request, ticket, client_redirect_url, session
        )


def _load_sso_handlers(hs: "HomeServer") -> None:
    """Ensure that the SSO handlers are loaded, if they are enabled by configuration.

    This is mostly useful to ensure that the CAS/SAML/OIDC handlers register themselves
    with the main SsoHandler.

    It's safe to call this multiple times.
    """
    if hs.config.cas.cas_enabled:
        hs.get_cas_handler()
    if hs.config.saml2.saml2_enabled:
        hs.get_saml_handler()
    if hs.config.oidc.oidc_enabled:
        hs.get_oidc_handler()
