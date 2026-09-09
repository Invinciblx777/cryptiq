"""The rule registry."""

from app.engine.rules import RsaRule, all_rules, get_rule, register, registered_rule_ids
from app.engine.rules.registry import _RULES


def test_the_rsa_rule_is_registered() -> None:
    rule = get_rule("PY-CRYPTO-RSA")

    assert isinstance(rule, RsaRule)
    assert rule.rule_id == "PY-CRYPTO-RSA"
    assert rule.version == "0.1.0"


def test_an_unknown_rule_is_absent() -> None:
    assert get_rule("PY-CRYPTO-ECDSA") is None


def test_only_the_rsa_rule_is_registered_in_this_phase() -> None:
    assert registered_rule_ids() == ("PY-CRYPTO-RSA",)


def test_rules_are_returned_in_a_stable_order() -> None:
    original = dict(_RULES)
    try:
        extra = RsaRule()
        extra.rule_id = "PY-CRYPTO-AAA"
        register(extra)

        assert [rule.rule_id for rule in all_rules()] == [
            "PY-CRYPTO-AAA",
            "PY-CRYPTO-RSA",
        ]
    finally:
        _RULES.clear()
        _RULES.update(original)
