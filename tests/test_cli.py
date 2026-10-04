from tinybrother.cli import main


def test_scan_missing_file_returns_2(capsys):
    assert main(["-q", "scan", "does-not-exist.evtx"]) == 2
    assert "not found" in capsys.readouterr().err


def test_scan_expands_wildcards(tmp_path, capsys):
    # no match for the pattern -> clean error instead of a crash
    assert main(["-q", "scan", str(tmp_path / "*.evtx")]) == 2
    assert "not found" in capsys.readouterr().err
