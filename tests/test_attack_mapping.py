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
