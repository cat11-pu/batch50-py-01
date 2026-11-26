# batch50-py-safety-b-04

## 题面

防火墙升级后，一台双网卡主机被 ICMP 重定向改错了默认路由，业务流量绕到错误的下一跳；另一台机器收到伪造的 fragmentation needed，把路径 MTU 改成 200，整条连接黑洞。范围是 gsb/batch50-py-safety-b-04 下的 icmp_redirect_guard.py，类 IcmpRedirectGuard，负责在主机侧校验入站 ICMP 重定向、不可达与需要分片报文，并维护路径 MTU 与判定缓存。

公开接口：IcmpRedirectGuard(*, local_networks, gateways, rate_limit=5, rate_window=1.0, cache_ttl=30.0, max_entries=256, min_ipv4_mtu=68, min_ipv6_mtu=1280)；on_icmp(packet, *, now=None)；route_changed(routes, *, now=None)；verdict(key, *, now=None)；path_mtu(destination)；purge_expired(*, now=None)；gateways()；routes()；stats()；snapshot()、restore(state)、close()。路由用 Route(destination, gateway, iface, metric=0)，判定用 Verdict(action, reason, kind)，拒绝抛 IcmpGuardError(code, detail)。packet 是字典，含 kind、src、dst、quoted，重定向另带 gateway，需要分片另带 mtu；now 是浮点秒。

故障与边界：①来源地址不在 gateways 内的报文一律 drop，reason 为 not_gateway；②重定向的新下一跳必须落在 local_networks 的直连网段内，仅校验来源是网关还不够；③引用报文的五元组必须齐全，缺字段 drop，reason 为 malformed；④按引用报文目的地址查最长前缀路由，路由不存在或下一跳与报文来源不一致时 drop，reason 为 quoted_mismatch；⑤多默认网关环境下，重定向只对发起它的那条路由生效，不能顺手改其它默认路由；⑥fragmentation needed 携带的 MTU 低于 IPv4 68 或 IPv6 1280 时忽略该报文，不得改写路径 MTU；⑦合法 MTU 接受后记录到 path_mtu，按目的地址可查；⑧不可达与重定向的判定按引用报文五元组缓存，超过 cache_ttl 后 verdict 返回 None；⑨route_changed 清空判定缓存与由重定向产生的路由覆盖，返回被清掉的缓存条数；⑩同一网关在 rate_window 内超过 rate_limit 条重定向要丢弃，reason 为 rate_limited，并累计告警；⑪缓存条目超过 max_entries 时淘汰最旧一条，计数可见；⑫close 之后所有入站报文 drop，reason 为 closed。

硬约束：一是判定、路由覆盖、速率窗口和缓存要在同一把锁内更新，并发报文不能出现半更新状态；二是 snapshot 固定包含 version、routes、redirects、cache、mtus、counters 六个键并返回深拷贝，restore 后路由、路径 MTU、缓存与计数一致，结构不合法或 version 不为 1 时抛 ICMP_SNAPSHOT_INVALID 且不改动现有状态。stats 至少给出 accepted、rejected、alerts、evicted、purged。

补充口径：quoted 是字典，至少含 src、dst、proto、sport、dport；kind 只认 redirect、unreachable、frag_needed，其它值按不支持丢弃。最长前缀命中多条时按 metric 最小，仍相同则取先加载的一条。IPv4 与 IPv6 的 MTU 下限分别判断，地址族从引用报文目的地址推断。缓存键就是引用报文的源地址、目的地址、协议、源端口、目的端口。速率窗口按网关分别计数，告警只在第一次超限时累计；路由覆盖只影响被重定向的那个目的地址，不替换整张路由表。被丢弃的报文不更新路径 MTU、不写判定缓存；接受的重定向 reason 为 ok，接受的分片报文 reason 为 path_mtu_updated，接受的重定向才产生覆盖路由。now 单位是秒，可以回退到更早时间做重放。

验收：在包目录执行 python3 -m pytest -q tests，15 条必须全过；不得修改测试、跳过或写死地址；并发、过期与恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: icmp_redirect_guard
- typeName: IcmpRedirectGuard
