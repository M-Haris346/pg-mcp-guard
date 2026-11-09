-- Audit log of every tool call (rule 9). Never holds result data, tokens or secrets.

CREATE TABLE audit.tool_calls (
    id          bigserial PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),
    user_id     uuid,          -- NULL only if no principal could be established
    tenant_id   uuid,
    tool        text NOT NULL CHECK (tool IN ('list_tables', 'describe_table', 'run_query')),
    sql_text    text,          -- NULL for tools that take no SQL
    verdict     text NOT NULL CHECK (verdict IN ('allowed', 'rejected', 'error')),
    reason      text,
    row_count   integer CHECK (row_count >= 0),
    truncated   boolean,
    duration_ms integer NOT NULL CHECK (duration_ms >= 0)
);

-- mcp_auditor may only append. No SELECT (it cannot read back what others
-- logged), no UPDATE / DELETE / TRUNCATE (it cannot rewrite history).
-- mcp_reader gets nothing here, not even USAGE on the schema.
GRANT USAGE ON SCHEMA audit TO mcp_auditor;
GRANT INSERT ON audit.tool_calls TO mcp_auditor;
GRANT USAGE ON SEQUENCE audit.tool_calls_id_seq TO mcp_auditor;
