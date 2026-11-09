"""Who is asking. The principal never comes from the model (CLAUDE.md rule 1).

Phase 4 adds JWT verification (stdio: at startup; HTTP: per request) that
produces a Principal. Tools take SQL only; they never accept identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True)
class Principal:
    user_id: UUID
    tenant_id: UUID
