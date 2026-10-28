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
)

from synapse.api.errors import (
    Codes,
    SynapseError,
)
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_json_object_from_request,
)
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class RefreshTokenServlet(RestServlet):
    PATTERNS = client_patterns("/refresh$")
    CATEGORY = "Registration/login requests"

    def __init__(self, hs: "HomeServer"):
        self._auth_handler = hs.get_auth_handler()
        self._clock = hs.get_clock()
        self.refreshable_access_token_lifetime = (
            hs.config.registration.refreshable_access_token_lifetime
        )
        self.refresh_token_lifetime = hs.config.registration.refresh_token_lifetime

    async def on_POST(self, request: SynapseRequest) -> tuple[int, JsonDict]:
        refresh_submission = parse_json_object_from_request(request)

        assert_params_in_dict(refresh_submission, ["refresh_token"])
        token = refresh_submission["refresh_token"]
        if not isinstance(token, str):
            raise SynapseError(400, "Invalid param: refresh_token", Codes.INVALID_PARAM)

        now = self._clock.time_msec()
        access_valid_until_ms = None
        if self.refreshable_access_token_lifetime is not None:
            access_valid_until_ms = now + self.refreshable_access_token_lifetime
        refresh_valid_until_ms = None
        if self.refresh_token_lifetime is not None:
            refresh_valid_until_ms = now + self.refresh_token_lifetime

        (
            access_token,
            refresh_token,
            actual_access_token_expiry,
        ) = await self._auth_handler.refresh_token(
            token, access_valid_until_ms, refresh_valid_until_ms
        )

        response: dict[str, str | int] = {
            "access_token": access_token,
            "refresh_token": refresh_token,
        }

        # expires_in_ms is only present if the token expires
        if actual_access_token_expiry is not None:
            response["expires_in_ms"] = actual_access_token_expiry - now

        return 200, response
