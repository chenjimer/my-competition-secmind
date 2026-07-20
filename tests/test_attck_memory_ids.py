from secmind.attck import AttackKnowledgeBase

TECHNIQUE = {
    "attack_id": "T1110",
    "name": "Brute Force",
    "description": "Try credentials repeatedly.",
    "tactics": ["credential-access"],
    "platforms": ["Windows"],
    "is_subtechnique": False,
    "detection": "Monitor failed logins.",
    "data_sources": ["Logon Session"],
}


def test_attack_documents_have_stable_domain_scoped_ids() -> None:
    enterprise = AttackKnowledgeBase(domain="enterprise")
    mobile = AttackKnowledgeBase(domain="mobile")

    first = enterprise.to_memory_documents([TECHNIQUE])[0]
    repeated = enterprise.to_memory_documents([TECHNIQUE])[0]
    other_domain = mobile.to_memory_documents([TECHNIQUE])[0]

    assert first.memory_id == repeated.memory_id
    assert first.memory_id != other_domain.memory_id
