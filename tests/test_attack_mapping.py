from tinybrother.attack.mapping import techniques_from_tags


def test_extracts_techniques_and_tactics():
    techs = techniques_from_tags(["attack.execution", "attack.t1059.001", "attack.T1027"])
    assert [t.technique_id for t in techs] == ["T1059.001", "T1027"]
    assert techs[0].tactics == ["execution"]


def test_tactic_styles_are_normalised():
    techs = techniques_from_tags(["attack.defense_evasion", "attack.credential-access", "attack.t1003"])
    assert techs[0].tactics == ["defense-evasion", "credential-access"]


def test_ignores_non_attack_tags():
    assert techniques_from_tags(["cve.2021-44228", "detection.threat_hunting"]) == []


def test_technique_names_are_bundled():
    from tinybrother.attack.mapping import technique_info, technique_label

    assert technique_label("T1059.001") == "PowerShell"
    assert technique_info("t1003.001")["parent"] == "OS Credential Dumping"
    assert technique_label("T9999") == "T9999"
    techs = techniques_from_tags(["attack.execution", "attack.t1059.001"])
    assert techs[0].name == "PowerShell"


def test_tactics_for_uses_attack_knowledge():
    from tinybrother.attack.mapping import tactics_for

    # T1003 is credential access, not resource development
    assert tactics_for("T1003", ["resource-development", "credential-access"]) == ["credential-access"]
    assert tactics_for("T1003", ["execution"]) == ["credential-access"]
    assert tactics_for("T9999", ["execution"]) == ["execution"]
    assert tactics_for("T9999", []) == ["unknown"]
