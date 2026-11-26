# batch50-py-safety-d-28

## 题面

内容平台的转码集群上个月被 IO 配额坑了两次。一次是父组收紧带宽后，子组之前借出去的额度还挂在表里，父组怎么压都压不下去，整台机器的写盘延迟翻了三倍；另一次是某台 NVMe 热拔之后，配额表里留着这个设备的借据，几个组的额度互相卡死，重启前谁也用不了。更早还有一次，转码组在两个盘上权重不一样，调度却按总带宽一把算，结果快盘被慢组拖死。范围是 gsb/batch50-py-safety-d-28 的 io_budget_partitioner.py，类名 IoBudgetPartitioner，负责 cgroup 层级下按设备分配 IO 带宽、借入借出、滑动窗口记账与回收。

公开接口：IoBudgetPartitioner()；add_device(name, *, capacity, window_seconds=10, windows=3)；remove_device(name)；add_group(name, *, parent=None, weight=100)；remove_group(name)；set_limit(device, group, *, limit, weight=None) -> dict；borrow(device, group, *, amount, ttl=30, now=None) -> dict；account(device, group, *, bytes_done, now=None) -> dict；reclaim(device, *, now=None) -> dict；rebalance(device, *, now=None) -> dict；status(device, group)；grants(device)；snapshot()；restore(state)；stats()。拒绝时统一抛 IoBudgetError(code, detail)。

故障与边界：①limit 必须是正整数，weight 取 1 到 1000，设备或组不存在报 IO_BUDGET_UNKNOWN，重复注册设备报 IO_BUDGET_EXISTS，参数与冲突拒绝计入 denied；②同一设备上已设限额的组按权重分基础份额，份额为 floor(capacity × weight ÷ 权重和)，余数按权重降序、组名字典序逐个补；超过自身 limit 的份额削掉后，释放的字节继续按剩余组权重分配，直到稳定；status 返回 limit、weight、share、used、effective_limit、available、borrowed_in、borrowed_out、over 与 window_used；③子组限额之和不得超过父组在该设备上的限额，否则报 IO_BUDGET_HIERARCHY 且不改动任何组；④未设限额的组调 status 报 IO_BUDGET_NO_LIMIT；⑤account 按实际完成字节累计，返回 used、window_used、over，bytes_done 非正整数报 IO_BUDGET_BAD_ACCOUNT；⑥用量按 window_seconds 切窗，window_used 只统计最近 windows 个窗口；连续三个窗口零用量的组在 rebalance 时权重临时翻倍作为饥饿保护；⑦borrow 只从其它组未使用的限额里按权重借，借据含 borrower、amount、lenders、expires_at 四个字段，额度不足整笔拒绝且不留借据；⑧借入额度到期时，未使用部分立即归还出借方；若借入组此时已超过自身限额，超出部分按每轮四分之一步降，不能瞬间掐断正在进行的 IO；⑨set_limit 收缩到低于已用加借出时，先作废该组作为出借方的未到期借据并累计 recalled 与 returned，仍低于已用则把限额压到已用值并把 clamped 置真；⑩设备被移除后，其它设备的配额表不受影响；该设备上未结清的借据要作废并把额度归还原出借方，不能留下悬空借据阻塞父组收紧；⑪同一组在不同设备上权重不同时，份额与借用必须按设备分别计算，不能把多块盘的带宽混在一起；⑫组删除要求没有子组，有子组报 IO_BUDGET_HAS_CHILDREN，借入或借出未结清报 IO_BUDGET_UNSETTLED。

硬约束：同一设备上的额度扣减、借用与回收必须持锁串行，份额重算与借据登记之间不得插入其它变更，额度要么整笔借出要么整笔不动；快照必须是深拷贝，保存设备容量、限额、权重、滑动窗口、借据与到期时间，恢复后借入借出关系原样可用，非法快照报 IO_BUDGET_SNAPSHOT_INVALID 且现有配额表不动。stats 返回 devices、groups、grants、borrows、borrow_denied、accounts、reclaimed_grants、denied，其中 groups 是已注册组数（含父组），denied 累计参数与冲突类拒绝。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: io_budget_partitioner
- typeName: IoBudgetPartitioner
