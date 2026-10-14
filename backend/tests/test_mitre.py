from app.intelligence.mitre import map_to_mitre_atlas


def test_instruction_override_mapping():

    result = map_to_mitre_atlas(
        "instruction_override"
    )

    assert result["mapped"] is True
    assert result["id"] == "AML.T0051"
    assert result["technique"] == "LLM Prompt Injection"
    assert result["tactic"] == "Execution"


def test_system_prompt_extraction_mapping():

    result = map_to_mitre_atlas(
        "system_prompt_extraction"
    )

    assert result["mapped"] is True
    assert result["id"] == "AML.T0056"
    assert result["technique"] == "Extract LLM System Prompt"
    assert result["tactic"] == "Exfiltration"


def test_unknown_mapping():

    result = map_to_mitre_atlas(
        "unknown"
    )

    assert result["mapped"] is False
    assert result["id"] is None
    assert result["technique"] is None
    assert result["tactic"] is None


def test_roleplay_mapping():

    result = map_to_mitre_atlas(
        "roleplay_manipulation"
    )

    assert result["mapped"] is True
    assert result["id"] == "AML.T0054"
    assert result["technique"] == "LLM Jailbreak"
    assert result["tactic"] == "Defense Evasion"


def test_safety_bypass_mapping():

    result = map_to_mitre_atlas(
        "safety_bypass"
    )

    assert result["mapped"] is True
    assert result["id"] == "AML.T0054"
    assert result["technique"] == "LLM Jailbreak"
    assert result["tactic"] == "Defense Evasion"