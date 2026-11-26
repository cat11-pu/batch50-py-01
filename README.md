# batch50-py-game-a-01

## 题面

据点战这周连着出问题：同一个石滩被三家公会抢了两轮，最终归属在两边对账时对不上；有的据点在换主人之后，冷却还没走完就又易主了，前一家的进度还被清得干干净净；服务器维护重启回来，几家公会的控制点全归零，争夺窗口的序号也从一开始重数，对账时连每轮的 tick 序号都对不上，无法证明哪家先到上限，运营只能按截图手工回补。范围是 gsb/batch50-py-game-a-01 的 territory_claim_ledger.py，类 TerritoryClaimLedger，按据点记录每个公会的争夺进度、当前归属、转移冷却与争夺窗口序号，供结算服务和对账脚本共用。

公开接口：TerritoryClaimLedger(*, claim_threshold=100, cooldown_ticks=5, max_contenders_per_site=8)；add_site(site_id, *, owner=None)；join_contest(site_id, guild, *, members, now=None)；leave_contest(site_id, guild, *, now=None)；tick(site_id, *, now=None)；settle(site_id, guild, *, now=None)；owner_of、progress_of、cooldown_left、contenders、state_of；snapshot、restore、stats。所有拒绝统一抛 TerritoryError(code, detail)，调用方按 code 分支处理。

故障与边界：①加入争夺时 members 必须为正整数、guild 去两端空格后不得为空，名单按加入顺序保留，重复加入只更新人数不产生重复项；②每轮 tick 按各公会当前人数累加控制点，单家进度封顶在 claim_threshold，离开的公会不再产出；③达到上限的公会按名称升序出现在 tick 返回的 ready 里，同一轮并列的公会顺序固定，重复跑同一批输入结果一致，返回值同时带 site_id、owner、cooldown_left、progress 与 suspended；④settle 要求该公会进度已到上限、仍在争夺名单内且不是当前归属方，否则分别报 TERRITORY_NOT_READY、TERRITORY_NOT_CONTENDING、TERRITORY_ALREADY_OWNER；⑤settle 成功后归属改写、所有公会进度清零、冷却置为 cooldown_ticks，claim 与 transfer 分别计数，transfer 只在上任归属非空时加一；⑥每次 tick 冷却减一，减到零为止，冷却期内进度达到上限只封顶并挂起，不得触发第二次易主；⑦leave_contest 会没收该公会已累计的进度并释放名额，未参战公会调用报 TERRITORY_NOT_CONTENDING；⑧单据点争夺名单有上限，超出报 TERRITORY_CAPACITY_EXCEEDED，被拒的加入不得改动名单；⑨空参数、非整数人数报 TERRITORY_INVALID_REQUEST，未知据点一律 TERRITORY_UNKNOWN_SITE，空 site_id 也不能悄悄建站点；⑩快照恢复后正在进行的争夺窗口按原 tick 序号续算，不从恢复时刻重新计时；⑪snapshot 返回 {"sites": ..., "stats": ...} 的深拷贝，restore 结构非法报 TERRITORY_SNAPSHOT_INVALID 且原状态不变；⑫stats 至少含 sites、joins、leaves、ticks、claims、transfers、refused_settles、capacity_refusals。

硬约束：并发加入、tick、settle 必须在同一把锁内完成，同一据点两个公会同时 settle 只能有一个成功，最终归属与各项计数一致；快照恢复后进度、封顶值、归属、冷却剩余与窗口序号都要在，且不得与调用方共享可变结构；长期运行下名单与统计只随存活据点增长，离开的公会不得继续占用名额或残留进度对象，所有对外返回的列表与字典都按稳定顺序生成。

验收：python3 -m pytest -q tests 15 条必须全过；不得改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现，不依赖外部服务。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: territory_claim_ledger
- typeName: TerritoryClaimLedger
