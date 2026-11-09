-- Phase 5: audit HTTP requests refused at authentication (401).
--
-- Such a request has no verified principal (user_id / tenant_id stay NULL:
-- claims of an unverified token are never trusted) and no tool, so the tool
-- column gets one more value, 'http_auth'. reason holds the internal cause,
-- e.g. 'invalid_token: expired'. The client only ever sees a generic 401.
-- Volume is rate-limited in the application (app/http_transport.py), so an
-- unauthenticated flood cannot fill this table.

ALTER TABLE audit.tool_calls DROP CONSTRAINT tool_calls_tool_check;
ALTER TABLE audit.tool_calls ADD CONSTRAINT tool_calls_tool_check
    CHECK (tool IN ('list_tables', 'describe_table', 'run_query', 'http_auth'));
