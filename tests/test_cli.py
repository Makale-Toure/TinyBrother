from tinybrother.cli import main


def test_scan_missing_file_returns_2(capsys):
    assert main(["-q", "scan", "does-not-exist.evtx"]) == 2
    assert "not found" in capsys.readouterr().err
