"""sec-ip-allowlist 的验收测试。

测试离线、确定性：不联网、不使用随机数、不依赖系统时钟。
只使用标准库 ipaddress 与 pytest。
"""

import ipaddress

import pytest

from ipallow.cidr import (
    allow_batch,
    contains,
    default_policy,
    family_ok,
    match,
    parse_allowlist,
    parse_rule,
    validate_allowlist,
)


def _v4(cidr: str) -> ipaddress.IPv4Network:
    return ipaddress.ip_network(cidr)


def _v6(cidr: str) -> ipaddress.IPv6Network:
    return ipaddress.ip_network(cidr)


def test_parse_rule_uses_prefix_as_network_bits():
    # Defect 1: prefix length is network bits, not a host count.
    rule = parse_rule("10.0.0.0/8 office")
    assert rule["cidr"] == "10.0.0.0/8"
    assert rule["version"] == 4
    assert rule["prefixlen"] == 8
    assert rule["note"] == "office"
    assert rule["network"].num_addresses == 2**24
    assert rule["network"].broadcast_address == ipaddress.ip_address("10.255.255.255")

    v6 = parse_rule("2001:db8::/32 core")
    assert v6["cidr"] == "2001:db8::/32"
    assert v6["version"] == 6
    assert v6["prefixlen"] == 32
    assert v6["note"] == "core"
    assert v6["network"].num_addresses == 2**96


def test_parse_rule_rejects_bare_address_and_wildcard():
    # Defect 2: a bare address must not be silently accepted as a whole rule.
    for bad in [
        "10.1.2.3",
        "2001:db8::1",
        "*",
        "any",
        "",
        "   ",
        "10.0.0.0/8/9",
        "10.0.0.1/8",
        "10.0.0.0/33",
    ]:
        with pytest.raises(ValueError):
            parse_rule(bad)


def test_contains_accepts_non_network_addresses():
    # Defect 3: containment is range containment, not equality with the network.
    net = _v4("10.0.0.0/24")
    assert contains(net, "10.0.0.1") is True
    assert contains(net, "10.0.0.254") is True
    assert contains(net, ipaddress.ip_address("10.0.0.200")) is True


def test_contains_does_not_do_string_prefix_matching():
    # Defect 4: 10.0.0.1 must not match 10.0.0.10 by string prefix.
    single = _v4("10.0.0.1/32")
    assert contains(single, "10.0.0.1") is True
    assert contains(single, "10.0.0.10") is False
    assert contains(single, "10.0.0.100") is False

    wide = _v4("10.0.0.0/24")
    assert contains(wide, "10.0.0.10") is True
    assert contains(wide, "10.0.1.0") is False


def test_family_ok_and_contains_reject_mixed_families():
    # Defect 5: mixed IPv4/IPv6 is a normal False, never an exception.
    v4 = _v4("10.0.0.0/8")
    v6 = _v6("2001:db8::/32")
    assert family_ok(v4, "10.1.2.3") is True
    assert family_ok(v6, "2001:db8::1") is True
    assert family_ok(v4, "2001:db8::1") is False
    assert family_ok(v6, "10.1.2.3") is False
    assert contains(v4, "2001:db8::1") is False
    assert contains(v6, "10.1.2.3") is False


def test_match_denies_address_outside_allowlist():
    # Defect 6: an unmatched address must be denied, not allowed by default.
    rules = parse_allowlist("10.0.0.0/8 office\n2001:db8::/32 core\n")
    assert match(rules, "10.1.2.3") is True
    assert match(rules, "2001:db8::5") is True
    assert match(rules, "192.168.1.1") is False
    assert match(rules, "2001:db9::1") is False
    assert match([], "10.1.2.3") is False


def test_default_policy_empty_denies():
    # Defect 7: an empty allowlist is deny-all, never allow-all.
    assert default_policy([]) == "deny"
    rules = parse_allowlist("10.0.0.0/8 office\n")
    assert default_policy(rules) == "deny"


def test_validate_flags_zero_prefix_as_too_broad():
    # Defect 8: 0.0.0.0/0 and ::/0 are wildcards, not valid intranet ranges.
    text = "0.0.0.0/0 wildcard\n::/0 wildcard-v6\n10.0.0.0/8 office\n"
    problems = validate_allowlist(text)
    broad = [p for p in problems if "broad" in p.lower()]
    assert len(broad) == 2
    assert not any("10.0.0.0/8" in p for p in broad)


def test_allow_batch_isolated_between_calls():
    # Defect 9: a later batch must not reuse the previous batch's networks.
    first = parse_allowlist("10.0.0.0/8 office\n")
    second = parse_allowlist("192.168.0.0/16 lab\n")
    addresses = ["10.1.1.1", "192.168.1.1"]

    first_result = allow_batch(first, addresses)
    second_result = allow_batch(second, addresses)

    assert first_result == {"10.1.1.1": True, "192.168.1.1": False}
    assert second_result == {"10.1.1.1": False, "192.168.1.1": True}
    assert allow_batch(first, addresses) == first_result


def test_parse_allowlist_skips_blank_and_comment_lines():
    # Defect 10: comment lines must be skipped, not parsed as rules.
    text = "\n   \n# 管理口\n10.0.0.0/8 office\n  # 另一段注释\n2001:db8::/32 core\n"
    rules = parse_allowlist(text)
    assert [r["cidr"] for r in rules] == ["10.0.0.0/8", "2001:db8::/32"]
    assert [r["note"] for r in rules] == ["office", "core"]


def test_network_and_broadcast_addresses_are_inside():
    # Boundary addresses are part of the range on both families.
    net = _v4("10.0.0.0/24")
    assert contains(net, "10.0.0.0") is True
    assert contains(net, "10.0.0.255") is True
    assert contains(net, "9.255.255.255") is False
    assert contains(net, "10.0.1.0") is False

    v6 = _v6("2001:db8::/64")
    assert contains(v6, "2001:db8::") is True
    assert contains(v6, "2001:db8::ffff:ffff:ffff:ffff") is True
    assert contains(v6, "2001:db8:0:1::") is False


def test_adjacent_networks_do_not_overlap():
    # Adjacent prefixes share a boundary but never contain each other.
    left = _v4("10.0.0.0/25")
    right = _v4("10.0.0.128/25")
    assert contains(left, right.network_address) is False
    assert contains(right, left.broadcast_address) is False
    assert contains(left, "10.0.0.127") is True
    assert contains(right, "10.0.0.128") is True

    left6 = _v6("2001:db8::/127")
    right6 = _v6("2001:db8::2/127")
    assert contains(left6, right6.network_address) is False
    assert contains(right6, left6.broadcast_address) is False


def test_empty_allowlist_denies_everything():
    # No rules means no trust: both single and batch paths deny.
    assert match([], "10.0.0.1") is False
    assert allow_batch([], ["10.0.0.1", "2001:db8::1"]) == {
        "10.0.0.1": False,
        "2001:db8::1": False,
    }
    assert default_policy([]) == "deny"


def test_invalid_lines_are_skipped_and_reported():
    # parse_allowlist skips bad lines; validate_allowlist still reports them.
    text = "10.0.0.0/8 office\nnot-a-network\n10.0.0.0/8 duplicate\n"
    rules = parse_allowlist(text)
    assert [r["cidr"] for r in rules] == ["10.0.0.0/8", "10.0.0.0/8"]

    problems = validate_allowlist(text)
    assert any("invalid" in p.lower() for p in problems)
    assert any("duplicate" in p.lower() for p in problems)


def test_batch_results_equal_individual_calls():
    # Batch decisions must equal one-by-one match decisions for every address.
    text = "10.0.0.0/8 office\n192.168.0.0/16 lab\n2001:db8::/32 core\n"
    rules = parse_allowlist(text)
    addresses = [
        "10.9.9.9",
        "192.168.1.1",
        "172.16.0.1",
        "2001:db8::1",
        "2001:db9::1",
    ]

    batch = allow_batch(rules, addresses)
    expected = {address: match(rules, address) for address in addresses}
    assert batch == expected
