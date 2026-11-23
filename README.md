# sec-ip-allowlist

## 题面

只对内网开放的管理接口，被一条写错一位的网段规则整段放行了：前缀长度被当成主机数，网段范围算错；不带前缀的裸地址被按三十二位处理，实际放行整段；包含判断只比较网络地址，同网段内其他地址被拒绝；包含判断用字符串前缀比较，点一命中点一零；地址族判断缺失，六版地址与四版网段比较时抛异常而不是返回不匹配；未命中时返回放行，默认动作反了；空名单的默认策略返回放行；名单校验不检查零前缀网段，全网段被当作合法内网；批量判定复用解析结果，后一批沿用前一批的网段；名单解析不跳过注释行，注释被当规则解析后整体异常。ipallow/cidr.py 是核心，tests/test_cidr.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

## 运行方式

在仓库根目录执行：

```powershell
python -m pytest tests -q
```

初始状态是可直接运行的失败环境：`ipallow/cidr.py` 中 8 个公开函数都是抛出 `NotImplementedError` 的桩，因此结果应恰好为 `15 failed`，不能出现 collection error，也不能出现 import 或 syntax error。

测试离线、不使用随机数、不依赖系统时钟；只使用 Python 标准库 `ipaddress`、`re` 和 pytest。

`tests/test_cidr.py` 是验收基准，不可修改；不要删除测试、跳过测试或放宽断言，只实现 `ipallow/cidr.py`。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 接口约定

- `parse_rule(rule) -> dict`：规则形如 `网段 备注`，网段必须带显式前缀；返回 `cidr`、`network`、`version`、`prefixlen`、`note` 五个键；裸地址、主机位非零、空串、前缀越界全部抛 `ValueError`。
- `parse_allowlist(text) -> list[dict]`：跳过空行、`#` 注释行和非法行，只返回合法规则，顺序不变。
- `contains(network, address) -> bool`：同族且落在网络地址到广播地址闭区间内为 `True`，跨族为 `False`；含网络地址和广播地址。
- `family_ok(network, address) -> bool`：同族 `True`，跨族 `False`，跨族不抛异常。
- `match(allowlist, address) -> bool`：任一规则命中为 `True`，否则 `False`；空名单为 `False`。
- `default_policy(allowlist) -> str`：始终返回 `deny`，空名单不得放行。
- `validate_allowlist(rules) -> list[str]`：`rules` 可为原文或规则列表；返回问题字符串，关键词为 `broad`、`invalid`、`duplicate`。
- `allow_batch(allowlist, addresses) -> dict`：返回地址到布尔值的映射，逐地址独立，结果与逐个调用 `match` 相同。
