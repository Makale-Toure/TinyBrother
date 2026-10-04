from tinybrother.storage.db import connect


def test_schema_created(tmp_path):
    conn = connect(tmp_path / "tb.db")
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"events", "alerts"} <= tables
