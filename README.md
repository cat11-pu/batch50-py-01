# batch50-py-safety-b-08

## 题面

客户端 VPN 上线后投诉集中在分流：访问内部财务系统时好时坏，抓包看到同一目的地址一会儿走隧道一会儿走本地；办公网 10 段和访客 172 段叠加后默认路由出现两条，系统随机选一条；断线重连后旧路由留在表里，重启机器又有残留。客户端日志里还能看到同一应用反复装路由、卸载路由，CPU 被占满。范围是 gsb/batch50-py-safety-b-08 的 split_tunnel_route_policy.py，类 SplitTunnelPolicy，负责把全局、租户、应用三层的包含排除网段编译成确定的路由计划，按最长前缀判定出口，并决定 DNS 走本地还是隧道。

公开接口：SplitTunnelPolicy(*, max_routes=512)；set_global(*, includes=(), excludes=(), default_via="tunnel")；set_tenant(tenant, *, includes=(), excludes=(), default_via=None, dns_mode="tunnel")；set_app(app, *, includes=(), excludes=(), dns_zones=(), dns_mode="tunnel")；compile(*, tenant=None, apps=(), now=None)；apply(plan, *, now=None)；remove(*, app=None)；reclaim()；explain(destination, *, tenant=None, apps=())；dns_route(name, *, tenant=None, apps=())；installed()；snapshot()、restore(state)、stats()。错误抛 RoutePolicyError(code, detail)。

故障与边界：①compile 返回 routes、default_via、dns、fingerprint、conflicts 五部分，隧道路由按前缀长度降序、同长度按网络地址升序，重复前缀只留一条。②包含与排除重叠时按最长前缀裁决，更具体的包含可以压过更宽的排除；反过来排除更具体时必须以排除为准，不能因为包含规则后加入就被覆盖。③完全落在排除里且没有更具体包含的目的地，explain 返回 local，matched_prefix 记为排除项，source 标明来源层。④应用集合顺序不影响结果，同一批应用正序与倒序编译出的 fingerprint 必须相同，指纹只由最终路由集合与 DNS 归属决定；同一前缀来自多个应用时取应用名字典序最小者。⑤默认路由只能有一个来源：全局与租户都声明 0.0.0.0/0 时只保留一条，取租户出口并累加 conflicts；未声明默认路由时 default_via 沿用全局或租户设置，租户显式声明 local 时不生成默认隧道路由。⑥DNS 归属按应用 dns_zones 最长后缀匹配，未命中回落租户 dns_mode；应用未配置 zones 时不参与匹配。⑦explain 返回 egress、matched_prefix、source 三个字段，source 为 global、tenant 或 app:名称，未命中时 source 为 default。⑧apply 只接受最近一次 compile 的结果，重复 apply 同一计划返回 0 且 installed 不变，首次 apply 返回新下发条数，installed 按编译顺序返回 CIDR 元组；版本不符报 UNKNOWN_PLAN；计划版本在每次 compile 时递增，旧计划再次 apply 必须被拒绝。⑨remove(app=...) 只撤该应用下发的路由，全局与租户路由保留；reclaim 撤掉全部并计数；回收计数按实际撤下的条数返回，重复回收同一应用返回 0。⑩路由条数超过 max_routes 报 ROUTE_LIMIT_EXCEEDED，不得截断后仍返回部分计划。⑪写入非法 CIDR 立即报 ROUTE_INVALID_CIDR；compile 引用未注册应用报 ROUTE_UNKNOWN_APP；空应用名报 INVALID_REQUEST。⑫IPv6 未单独配置分流但隧道已启用时，DNS 与默认路由不得泄漏到本地出口。快照含 version、global、tenants、apps、stats 五个顶层键并深拷贝，非法结构报 ROUTE_SNAPSHOT_INVALID 且原状态不变。

硬约束：编译结果必须确定，相同输入的 fingerprint 稳定，与应用传入顺序、字典遍历顺序无关；断线或策略变更要按应用精确回收已下发路由，快照恢复后已下发路由一律视为已回收，不得残留；规则条数与单次编译耗时都有上限。stats 返回 compiled、applied、removed、reclaimed、conflicts、limit_rejected。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: split_tunnel_route_policy
- typeName: SplitTunnelPolicy
