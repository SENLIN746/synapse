/* Native account/attempt binding and hashed, device-bound bootstrap grants.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2026 AgentIM contributors
 */
CREATE TABLE agentim_initial_accounts (
    attempt_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE,
    device_id TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    expires_ts BIGINT NOT NULL,
    completed BOOLEAN NOT NULL DEFAULT FALSE,
    grant_hash TEXT,
    grant_expires_ts BIGINT,
    grant_used BOOLEAN NOT NULL DEFAULT FALSE
);
