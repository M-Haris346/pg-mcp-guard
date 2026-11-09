# Demo video: shot list (2–3 minutes)

Recording setup: a terminal at about 110 columns, large font; the README open in a browser for the
diagram. Run `uv run python scripts/dev_setup.py` beforehand, so the recording starts from a ready
database.

| # | Time | Shot | Narration |
|---|---|---|---|
| 1 | 0:00–0:15 | README "Why" section, highlighting `COMMIT; DROP ...` | "MCP lets an AI agent query your database. The reference Postgres server ran the model's SQL in a read-only transaction, and one string, `COMMIT; DROP`, walked straight out of it. A filter on the SQL text is one layer. This project adds the others." |
| 2 | 0:15–0:35 | README layers diagram, then the sequence diagram | "The database comes first: a least-privilege role, column grants, and row-level security keyed to a signed, short-lived identity that Postgres verifies itself. On top of that, a validator built on Postgres's own parser, an executor with hard limits, and an audit row for every call." |
| 3 | 0:35–0:45 | Terminal: `uv run python scripts/demo.py --pause`, header visible | "This is the real server, driven by a real MCP client. I'm Alice from Acme. I never choose who I am: my identity comes from a signed token." |
| 4 | 0:45–0:55 | Scene a: `list_tables` | "The model sees only what it may read. No users table, and no customer email or phone columns." |
| 5 | 0:55–1:05 | Scenes b and c | "Acme has four orders. Asking for Globex's orders isn't an error, it's just zero rows: row-level security filters them out in the database." |
| 6 | 1:05–1:15 | Scene d | "Emails and phone numbers are refused by a column grant. The validator lets this through on purpose; the database is the control." |
| 7 | 1:15–1:30 | Scenes e and f | "Dropping a table is refused. And the exact Datadog escape, `COMMIT; DROP TABLE`, is refused too. Even with the validator switched off, the driver protocol and the read-only, owner-less role stop it." |
| 8 | 1:30–1:45 | Scenes g and h | "A thirty-second sleep is refused. And trying to become Globex by forging the context: refused by the validator, and by the database too, which won't let this role change any setting and rejects unsigned contexts." |
| 9 | 1:45–2:05 | Scene i, the fenced result | "Results come back fenced and labelled as untrusted data. This row says 'ignore previous instructions'. It's treated as data, and nothing inside the data can close the fence." |
| 10 | 2:05–2:20 | Scene j, the audit rows | "Every call was audited: allowed, rejected or error, with the reason. Written by a separate role that can only insert. And if the audit write fails, the caller gets no result." |
| 11 | 2:20–2:40 | Terminal: `uv run pytest tests/db -q` passing, then `tests/db/test_set_config.py` in the editor | "Most database tests run with the validator disabled, to prove Postgres holds on its own. Our own gap check found that SQL could still change settings like `work_mem`. That's closed now, and there's a test for it." |
| 12 | 2:40–2:50 | README "Limitations", then the threat model | "What it doesn't do: it can't stop a client from passing rows it may read to another tool, HTTP needs TLS in front, and HS256 means the operator can mint identities. It's all in the threat model." |

Notes:
- Keep the terminal output exactly as the script prints it; don't edit it in post.
- If a scene prints `UNEXPECTED`, stop and fix the setup: the script exits non-zero in that case.
