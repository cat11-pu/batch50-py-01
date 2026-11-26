# batch50-py-safety-c-23

## 题面

红队演练环境上周出了两次事故：一次是操作员把授权清单里的 /24 写成了 /16，脚本照着放行动作，直接把测试流量打到了办公网段；另一次是单目标动作被循环重试，十秒内打出上千次请求，把演练靶机打挂，演练组只能临时停机。更麻烦的是，熔断触发之后，几个已经在途的动作被后台当成成功记了账，复盘报告里看着一切正常。范围是 gsb/batch50-py-safety-c-23 下的 simulation_safety_interlock.py，类名 SimulationSafetyInterlock，负责目标范围校验、动作放行的速率预算、全局熔断与冷却复位。

公开接口：SimulationSafetyInterlock(*, global_rate=20, per_target_rate=5, window_seconds=10, cooldown_seconds=60)；register_scope(scope_id, *, cidrs)；arm(run_id, *, scope_id, now)；disarm(run_id, *, now)；check_action(run_id, *, action_id, target, now)；finish_action(permit_id, *, outcome, now)；trip(*, reason, now)；reset(*, now)；status(*, now=None)；permits(*, run_id=None)；report()；stats()、snapshot()、restore(state)。拒绝时抛 InterlockError(code, detail)。

故障与边界：①scope 标识不能为空，cidrs 至少一条且必须能解析成网段，空标识抛 INTERLOCK_INVALID_REQUEST，非法网段抛 INTERLOCK_BAD_SCOPE；同一 scope 重复登记抛 INTERLOCK_SCOPE_EXISTS，登记失败不得留下半条记录。②arm 要求 scope 已登记、run_id 去空白后非空且未登记过，分别抛 INTERLOCK_SCOPE_UNKNOWN、INTERLOCK_INVALID_REQUEST、INTERLOCK_RUN_EXISTS；成功时返回 run_id、scope_id、state 与 armed_at。③目标是单个 IP 地址，必须落在授权网段内才放行；传网段字符串或非法地址抛 INTERLOCK_BAD_TARGET，落在所有授权网段之外抛 SCOPE_TARGET_DENIED，被拒的动作不得占用预算。④check_action 返回 permit_id（从 P-0001 递增）、run_id、action_id、target、state 为 in_flight、granted_at；同一 run 内 action_id 重复抛 INTERLOCK_DUPLICATE_ACTION，不同 run 之间互不影响。⑤速率预算按固定窗口 now // window_seconds 计数，先判全局再判单目标：全局用满抛 RATE_GLOBAL_EXCEEDED，单目标用满抛 RATE_TARGET_EXCEEDED，进入下一个窗口后预算恢复。⑥finish_action 只接受 ok 与 failed，未知令牌抛 INTERLOCK_PERMIT_UNKNOWN，已结算抛 INTERLOCK_PERMIT_SETTLED，其它取值抛 INTERLOCK_INVALID_REQUEST。⑦只有 armed 状态的运行能放行动作，未知运行抛 INTERLOCK_RUN_UNKNOWN，已解除武装抛 INTERLOCK_RUN_STATE；disarm 也只对 armed 有效，返回 run_id、state、disarmed_at。⑧trip 要求原因去空白后非空，立刻把全部运行置为 tripped、冻结在途令牌并拒绝新的 arm 与 check_action（INTERLOCK_TRIPPED）；trip 返回 tripped_runs、frozen_permits、reason、tripped_at，熔断时已经在途的动作要标记为未完成，不得计为成功。⑨reset 只对 tripped 有效，返回 reset_at 与 cooling_until（tripped_at 加 cooldown_seconds），其它情况抛 INTERLOCK_NOT_TRIPPED；冷却期内即使复位成功也不得放行新动作，越界抛 INTERLOCK_COOLING_DOWN。⑩冷却期满后才允许重新 arm；status 返回 state、armed_runs、in_flight、trips、cooling_remaining，cooling_remaining 按传入 now 计算且不得为负。⑪permits 按 permit_id 升序返回并可按 run_id 过滤；report 返回 actions、in_flight、completed、failed、voided 五项。⑫stats 返回 scopes、runs、permits、trips、resets 五项计数；非法快照抛 INTERLOCK_SNAPSHOT_INVALID，且不得改动现有 scope、运行、令牌与计数；快照键为 format、scopes、runs、permits、switch、counters。

硬约束：同一令牌的放行与结算必须串行，速率计数在并发下不得超发，多个运行共享全局预算但各自维护动作去重；快照必须与活动状态完全脱钩，恢复后 scope、运行状态、令牌状态、预算窗口、熔断与冷却时间、五项计数原样回来，已熔断的运行不得借快照回到 armed 状态。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: simulation_safety_interlock
- typeName: SimulationSafetyInterlock
