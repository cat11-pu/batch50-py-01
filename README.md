# batch50-py-safety-c-05-p2

## 题面

上周一次发布把两条链路拖下水：一个只该绑 80 端口的网关单元，因为单元文件里抄了邻居的能力集，启动后拿到了改网络配置的权限，顺手把宿主路由表改坏；另一条更隐蔽，某单元启动失败触发回滚，回滚脚本为了恢复原状，把已经降权的进程重新提回 root，失败单元的半截配置被写进了系统目录。事后翻发布记录，依赖顺序靠人工排、能力集靠复制粘贴，闸门一条都没有。范围是 gsb/batch50-py-safety-c-05-p2 的 unit_privilege_gate.py，类 UnitPrivilegeGate，负责服务单元注册时的权限校验、启动前的依赖链检查、启动顺序与失败回滚；入口一调用就抛 NotImplementedError。

公开接口：UnitPrivilegeGate(*, max_units=128)；register_unit(name, user, capabilities, no_new_privs=True, requires=())、unit_spec(name)、units()、effective_capabilities(name)、plan_start(name)、start_unit(name, now)、stop_unit(name, cascade=False, now)、start_batch(names, now)、unit_state(name)、running_units()、audit_entries()、snapshot()、restore(state)、stats()。启动计划带 target、ordered、effective，启动结果带 unit、state、started、effective_caps，停止结果带 unit、stopped、outcome，批量结果带 status、started、rolled_back、failed、code，审计条目带 seq、action、unit、outcome、code、caps。拒绝一律抛 UnitGateError(code, detail)。

故障与边界：①单元名只允许小写字母、数字、点、下划线与连字符，长度不超过 64，重复注册报 UNIT_ALREADY_REGISTERED，超过 max_units 报 UNIT_CAPACITY_EXCEEDED；②能力集只接受列表或元组，单个字符串与未知能力名分别报 UNIT_INVALID_REQUEST 与 UNIT_UNKNOWN_CAPABILITY，合法项去重排序；③非 root 用户声明 root 专属能力报 UNIT_PRIVILEGE_ESCALATION，非 root 单元未开 no_new_privs 报 UNIT_NO_NEW_PRIVS_REQUIRED，不能靠启动参数事后补；④依赖单元的权限不得被下游继承，即使下游声明了同样的能力，下游的有效能力只由自己的声明与用户决定，依赖链只决定顺序；⑤plan_start 按依赖名字典序深度优先展开，先依赖后自身，ordered 不含重复；依赖名在注册时允许暂时不存在，存在性只在 plan_start 校验，自依赖与环报 UNIT_DEPENDENCY_CYCLE，依赖不存在报 UNIT_UNKNOWN_DEPENDENCY；⑥start_unit 要求所有依赖都处于 running，否则报 UNIT_DEPENDENCY_NOT_RUNNING 且本单元状态不变；⑦已运行的单元再次启动返回 started=False，不计入 started；⑧有下游在运行时 stop_unit 报 UNIT_DEPENDENTS_RUNNING，cascade=True 才按依赖逆序停掉整棵子树；⑨start_batch 逐个单元展开依赖启动，中途任一单元计划或启动失败，已启动的单元按逆序回滚，回滚时已降权的单元必须先停后回滚，任何一步不得反向提权，失败结果里带 failed 单元名与 code，status 取 ok 或 rolled_back；⑩stop 与回滚后的单元状态为 stopped，停止成功的 outcome 为 stopped，能力集清空，running_units 按名字排序且不再包含它；⑪审计记录 action、unit、outcome、code、caps，序号从 1 连续递增；⑫快照固定为 version、units、audit、counters、stats 五个键且是深拷贝，restore 缺键、版本不符或类型不对报 UNIT_SNAPSHOT_INVALID 且原状态不动，恢复后单元状态、审计序号与统计继续可用。

硬约束：同一单元上的启动、停止、批量回滚必须串行，多个调用并发启动同一单元只能产生一条 started=True，其余返回已运行，started 计数不得翻倍；批量回滚要么全部回到启动前状态，要么一个都不动，不能留下半启动的单元。stats 固定含 registered、started、stopped、rolled_back、refused、plans、audit_writes、already_running。

验收：`python3 -m pytest -q tests` 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch50-py-safety-c-05-p2
- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: unit_privilege_gate
- typeName: UnitPrivilegeGate
- file: unit_privilege_gate.py
