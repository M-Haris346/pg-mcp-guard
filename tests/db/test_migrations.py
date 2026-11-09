from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from scripts.migrate import MIGRATIONS_DIR, MigrationError, apply_migrations
from tests.db.helpers import DbTestSettings


def test_second_run_is_a_no_op(db_settings: DbTestSettings) -> None:
    # The session fixture already migrated the test database.
    assert apply_migrations(db_settings.test_migrator_database_url.get_secret_value()) == []


def test_edited_applied_migration_is_refused(db_settings: DbTestSettings, tmp_path: Path) -> None:
    copy = tmp_path / "migrations"
    shutil.copytree(MIGRATIONS_DIR, copy)
    first = sorted(copy.glob("*.sql"))[0]
    first.write_text(first.read_text(encoding="utf-8") + "\n-- edited\n", encoding="utf-8")

    with pytest.raises(MigrationError, match=f"{first.name} changed after it was applied"):
        apply_migrations(db_settings.test_migrator_database_url.get_secret_value(), copy)
