# batch50-py-safety-c-11

## 题面

终端防护团队复盘了两起金丝雀令牌失效事故：一支放在对象存储配置里的诱饵访问密钥被外部爬虫调用，值班同学三小时后才从账单侧发现；另一支同批次下发的诱饵 Webhook 在同一分钟内被连续触发十几次，告警被刷成一片，真正需要处置的第一次命中反而被埋掉。更麻烦的是服务重启之后登记表只剩内存里最后几条，哪些令牌因为命中失效、哪些资产已经冻结完全说不清。范围是 gsb/batch50-py-safety-c-11 下的 canary_token_registry.py，类名 CanaryTokenRegistry：负责诱饵令牌的签发登记、命中上报的时间窗去重、命中后的批次吊销级联与关联资产冻结，并把登记表序列化以便重启恢复。

公开接口：CanaryTokenRegistry(*, hit_window_seconds=300)；issue(token_id, *, purpose, placement, batch_id, owner, now)；bind_asset(token_id, asset_id)；report_hit(token_id, *, source, now)；revoke(token_id, *, reason, now)；cascade(batch_id, *, reason, now)；status(token_id)；tokens(*, batch_id=None)；frozen_assets()；snapshot()；restore(state)；stats()。拒绝时抛 CanaryError(code, detail)，令牌用只读对象 CanaryToken 返回，时间参数与回执统一为带 +00:00 偏移的 ISO 8601 字符串。

故障与边界：①issue 要求 token_id、purpose、placement、batch_id、owner 均为非空字符串，重复 token_id 抛 CANARY_DUPLICATE_TOKEN，字段不合法抛 CANARY_BAD_REQUEST，失败不得留下半条登记。②令牌状态只有 active、triggered、revoked 三种；首次非去重命中把令牌置为 triggered 并冻结其名下资产，同批次其余 active 令牌级联吊销，返回值 cascaded 是本次新吊销的数量，命中产生的冻结原因记为 canary_hit。③命中上报按 hit_window_seconds 计算时间窗：距上次命中不超过窗口的重复触发 deduped 为真、不再触发级联，但 hits 必须继续累加。④超过窗口的再次触发 deduped 为假，要重新走一次评估；无论去重与否 last_hit_at 都更新为本次时间。⑤已吊销令牌再次被上报命中时仍要记录这次触发并累加计数，但不得再触发一次批次吊销，也不得重复冻结已经冻结过的资产。⑥同一批次里若已有令牌被单独吊销过，批次级联不得因为再次吊销而中途失败，返回里要区分新吊销与本就吊销的数量。⑦revoke 不存在的令牌抛 CANARY_UNKNOWN_TOKEN，对已吊销令牌重复 revoke 是无操作而非报错，返回 token_id、changed 与 frozen_assets；吊销不可逆。⑧bind_asset 对未知令牌抛 CANARY_UNKNOWN_TOKEN，同一令牌重复绑定同一资产只保留一份，资产按字符串升序；frozen_assets 按资产标识升序，同一资产被多支令牌关联时只记首次冻结的令牌与原因。⑨cascade 对没有任何登记记录的批次抛 CANARY_UNKNOWN_BATCH；显式级联与命中触发的级联都要冻结被吊销令牌名下资产。⑩status 对未知令牌抛 CANARY_UNKNOWN_TOKEN，返回至少包含 token_id、state、hits、last_hit_at、batch_id、assets 以及吊销时间和原因。⑪登记表快照包含版本号、令牌、资产绑定、冻结台账与计数，快照必须与活动数据完全脱钩；恢复非法结构抛 CANARY_SNAPSHOT_INVALID 且不改动现有登记。⑫重启后命中计数、最后命中时间、吊销与冻结状态原样回来，不得重新计时；stats 返回 issued、hits、deduped、escalated、revoked、frozen 六项。

硬约束：登记、命中上报与级联必须串行，同一令牌被多线程同时上报时计数不得丢失、去重判定以串行结果为准、一次命中只允许产生一次级联，级联持锁期间不得插入新的签发；快照恢复期间任何拒绝都不得留下部分写入，且不得把 revoked 或 triggered 令牌改回 active。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: canary_token_registry
- typeName: CanaryTokenRegistry
