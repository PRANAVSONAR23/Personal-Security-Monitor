from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from psm.store.db import open_db


@pytest.fixture()
def db(tmp_path: Path) -> Iterator:
    conn = open_db(tmp_path / "psm.sqlite")
    try:
        yield conn
    finally:
        conn.close()
