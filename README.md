# batch50-py-safety-d-05

## 题面

视频网关这周被投诉得最凶：跨地域通话里，两端同时发提名，各自都以为自己选好了路径，结果一路走加密隧道、一路走直连，媒体流在中间来回跳；还有一次候选对刚校验通过，底层候选被移除，进程仍然按已选路径发包，包全被丢弃，通话静音十几秒才恢复；更麻烦的是 consent 刷新和路径切换撞在一起，旧路径迟到的响应把选择改了回去，用户听到一半直接断线。监控同学还补充说，切换期间统计口径也对不上，两条路径的在途包被重复计数，报表上出现了单通电话两份码率。运维的要求很明确：读出来的 selected 必须仍然是 valid 且 consent 没有过期，trickle 迟到的高优先级候选不能推翻已经选好的路，重选必须有明确触发点。范围是 gsb/batch50-py-safety-d-05 下的 ice_consent_guard.py，类名 IceConsentGuard，负责候选入库、候选对校验、提名、consent 与选路。

公开接口：IceConsentGuard(*, max_candidates=16, max_pairs=32, consent_ttl=6, max_consent_failures=2, role="controlling")；add_candidates(candidates, side, now)、resolve_role(local_role, local_tie_breaker, remote_role, remote_tie_breaker)、check_pair(pair_id, responded=True, failed=False, now=None)、nominate(pair_id, replace=False, now=None)、consent(pair_id, ok, now=None)、select(now)、remove_candidate(key)、pairs()、status()、snapshot()、restore(state)、stats()。拒绝统一抛 IceError(code, detail)。候选是含 foundation、component、transport、address、port、priority 的 dict，候选键写作 transport://address:port，候选对优先级等于本地优先级乘一千加远端优先级；status() 返回 role、selected、candidates、pairs、valid、nominated 六个字段。返回结构固定：add_candidates 给 Candidate(key, foundation, component, transport, address, port, priority, side)，check_pair 与 pairs 给 PairReport(pair_id, state, priority, nominated, consent_until)，nominate 给 NominationReport(pair_id, state, nominated, role)，consent 给 ConsentReport(pair_id, state, failures, consent_until, selected)，select 给 Selection(pair_id, state, consent_until)。

故障与边界：①side 只接受 local 与 remote，缺字段、端口越界、优先级非整数报 ICE_INVALID_REQUEST；②同一 side 上相同 foundation 只保留优先级最高的一条，替换计入 candidates_replaced；③每侧候选数与候选对总数各自封顶，超出报 ICE_CANDIDATE_LIMIT / ICE_PAIR_LIMIT，整批拒绝、不留半截；④候选对建立后为 waiting，没收到响应前不得进入 valid，responded 为假时最多算 in-progress；⑤校验失败置 failed 并清掉 consent，select 不得选它；⑥双方同为 controlling 时由 tie-breaker 决胜，落败方转 controlled，非法角色报 ICE_INVALID_ROLE；⑦只有 controlling 侧可以提名，非 controlling 提名报 NOMINATION_FORBIDDEN；⑧提名要求候选对已 valid，未通过报 ICE_PAIR_NOT_VALID，同一时刻最多一个 nominated，改提名必须显式 replace，否则报 NOMINATION_CONFLICT；⑨valid 时给出初始 consent 截止时间，consent 成功顺延 consent_ttl，连续失败达到 max_consent_failures 即置 invalid 并清空选择；⑩select 只在 valid 且 consent 未过期的候选对里按优先级取最高，没有可用路径报 NO_VALID_PAIR；⑪已选路径仍然有效时保持粘住，trickle 迟到的高优先级候选不能推翻它，只有重选之后才能接管；⑫双方同时发送 nomination 时只能有一个提名生效，落败方回退而不是产生两条 selected；consent 刷新与路径切换并发时，旧路径的迟到响应不能把已切换的选择改回去；候选对在 valid 之后其底层候选被移除，必须级联失效并触发重选。

硬约束：候选增删、校验、提名、consent 与选路共用一把 threading.RLock，读到的 selected 必须仍为 valid 且 consent 未过期；快照深拷贝，含 version、candidates、pairs、role、selection、counters 六个键，恢复后选择与 consent 截止时间必须一致，非法结构抛 ICE_SNAPSHOT_INVALID 且不改动现有状态。stats 固定返回 candidates_added、candidates_replaced、pairs_created、checks、valid、failed、nominations、consents、reselects 九个键。

验收：`python3 -m pytest -q tests` 15 条必须全过；不得修改测试、跳过或用固定输入写死；并发与重启场景自行构造验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch50-py-safety-d-05
- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: ice_consent_guard
- typeName: IceConsentGuard
- topic: ICE 连通性检查与同意新鲜度：候选对提名、角色冲突与双路径切换
