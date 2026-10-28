/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2026 AgentIM contributors
 */
ALTER TABLE agentim_initial_accounts ADD COLUMN native_ready BOOLEAN NOT NULL DEFAULT FALSE;
CREATE UNIQUE INDEX agentim_initial_grant_hash ON agentim_initial_accounts(grant_hash)
    WHERE grant_hash IS NOT NULL;
