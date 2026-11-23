"""内网管理接口的 IP 允许名单核心逻辑。

本模块只依赖标准库 ipaddress 与 re。

全局约定：

- 网段使用 ipaddress.IPv4Network 或 ipaddress.IPv6Network 对象表示。
- 地址既可以是 ipaddress 的地址对象，也可以是可被 ipaddress.ip_address
  解析的字符串。
- 容差为 0：只做协议规定的地址归一化，不做字符串前缀、后缀、模糊或
  隐式补位匹配。
- IPv4 与 IPv6 严格隔离；跨族一律视为不匹配，不得抛异常。
- 允许名单是白名单模型：只有显式命中规则才放行，其余一律拒绝。
"""

from __future__ import annotations

import ipaddress
import re

__all__ = [
    "parse_rule",
    "parse_allowlist",
    "contains",
    "family_ok",
    "match",
    "default_policy",
    "validate_allowlist",
    "allow_batch",
]


def parse_rule(rule: str) -> dict:
    """解析单条规则，返回规格化后的规则字典。

    规则语法（容差 0）::

        <CIDR> [空白 <备注>]

    CIDR 必须显式写出前缀长度，例如 10.0.0.0/8 或 2001:db8::/32。
    任何不合法输入一律抛出 ValueError，不得静默修正。
    """

    if not isinstance(rule, str):
        raise ValueError("rule must be a string")

    text = rule.strip()
    if not text:
        raise ValueError("empty rule")

    # 备注是第一个空白之后的全部内容（保留内部空白），首尾空白去掉。
    parts = text.split(None, 1)
    cidr_text = parts[0]
    note = parts[1].strip() if len(parts) > 1 else ""

    # CIDR 必须显式写出前缀长度，且只能有一个斜杠；裸地址、多个斜杠、
    # 通配符等一律拒绝。
    if cidr_text.count("/") != 1:
        raise ValueError(f"rule must be an explicit CIDR: {cidr_text!r}")

    # strict=True：主机位非零的网段（如 10.0.0.1/8）直接拒绝。
    # 前缀长度按网络位数解释，由 ipaddress 完成解析与越界检查。
    try:
        network = ipaddress.ip_network(cidr_text, strict=True)
    except ValueError as exc:
        raise ValueError(f"invalid CIDR {cidr_text!r}: {exc}") from exc

    return {
        "cidr": str(network),
        "network": network,
        "version": network.version,
        "prefixlen": network.prefixlen,
        "note": note,
    }


def parse_allowlist(text: str) -> list[dict]:
    """逐行解析允许名单文本，返回规则字典列表。

    空行与 # 注释行整行跳过；解析失败的行跳过，不向上抛异常。
    """

    rules: list[dict] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            continue
        try:
            rules.append(parse_rule(stripped))
        except ValueError:
            continue
    return rules


def _coerce_address(address):
    """把地址统一成 ipaddress 地址对象；非法地址抛 ValueError。"""
    if isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return address
    return ipaddress.ip_address(address)


def contains(network, address) -> bool:
    """判断地址是否落在网段内，包含网络地址与广播地址。

    跨族返回 False，不得抛异常；不做任何字符串前缀比较。
    """

    addr = _coerce_address(address)
    if not isinstance(network, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        raise ValueError("network must be an IPv4Network or IPv6Network")
    if addr.version != network.version:
        return False
    return network.network_address <= addr <= network.broadcast_address


def family_ok(network, address) -> bool:
    """判断网段与地址是否属于同一地址族；跨族返回 False，绝不抛异常。

    地址字符串本身非法时抛出 ValueError。
    """

    addr = _coerce_address(address)
    return addr.version == network.version


def match(allowlist, address) -> bool:
    """判断地址是否命中允许名单中的任一规则；命中即放行，否则拒绝。"""

    for rule in allowlist:
        network = rule["network"]
        if family_ok(network, address) and contains(network, address):
            return True
    return False


def default_policy(allowlist) -> str:
    """允许名单是白名单：未命中一律拒绝，空名单同样拒绝。"""

    return "deny"


def validate_allowlist(rules) -> list[str]:
    """检查允许名单并返回问题描述列表；没有问题时返回空列表。"""

    problems: list[str] = []

    if isinstance(rules, str):
        parsed: list[dict] = []
        for line in rules.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                parsed.append(parse_rule(stripped))
            except ValueError:
                problems.append(f"invalid rule line: {stripped}")
    else:
        parsed = list(rules)

    seen: set[str] = set()
    for rule in parsed:
        cidr = rule["cidr"]
        if rule["prefixlen"] == 0:
            problems.append(f"broad rule matches every address: {cidr}")
        if cidr in seen:
            problems.append(f"duplicate rule: {cidr}")
        else:
            seen.add(cidr)

    return problems


def allow_batch(allowlist, addresses) -> dict:
    """批量判定一组地址，每个地址完全独立判定，不复用任何缓存。"""

    results: dict = {}
    for address in addresses:
        key = address if isinstance(address, str) else str(address)
        # 非法地址在此抛出 ValueError（由 _coerce_address 触发）。
        results[key] = match(allowlist, address)
    return results
