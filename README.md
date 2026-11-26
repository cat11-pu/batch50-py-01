# batch50-py-game-a-08-p5

## 题面

边境服的通缉系统这一周被玩家摸透了。有人在无人区撬了三间仓库，系统照样在另外两个辖区给他挂了赏金，等于凭空多出一笔钱；另一头，赏金猎人刚领走悬赏，目标玩家的通缉热度直接清零，回城时守卫连看都不看一眼；还有一起跨区案件，两个辖区的热度各自都远不到上限，引渡合并之后总热度却顶穿了上限，通缉榜的排序当场乱掉。范围是 gsb/batch50-py-game-a-08-p5 的 wanted_heat_ledger.py，类 WantedHeatLedger，负责辖区热度累计、目击者证词、按时间衰减、赏金计算与领取、清除通缉，以及状态快照。

公开接口：WantedHeatLedger(*, heat_cap=1000, bounty_cap=50000, heat_per_bounty=10, bounty_unit=100, bounty_per_witness=50, decay_interval=60, decay_step=10, clear_cooldown=120, fine_per_heat=5, max_regions=16)；add_heat(player, region, amount, *, now=None)、witness(player, region, witness_id, *, now=None)、decay(player, *, now=None)、heat(player, region=None)、bounty(player)、claim_bounty(player, region, claimant, *, now=None)、clear(player, region, *, now=None, payment=0)、records(player)、list_wanted(*, min_heat=1)、extradite(player, source, target)、snapshot()、restore(state)、stats()。拒绝一律抛 WantedError(code, detail)。

故障与边界：①时间一律用 ISO8601 字符串，解析失败、玩家名或辖区名为空、amount 非正整数、payment 为负都报 WANTED_INVALID_REQUEST，同一玩家的事件时间早于最后事件时间报 WANTED_CLOCK_REGRESSION；②热度按辖区累计并在 heat_cap 处截断，add_heat 返回截断后的热度与最后事件时间；③每个玩家最多同时挂着 max_regions 个辖区，超限报 WANTED_CAPACITY_EXCEEDED 且不新增；④目击者编号去空白后不得为空，重复编号不重复计数，列表按编号升序；⑤辖区赏金等于目击者数乘 bounty_per_witness 加上热度整除 heat_per_bounty 再乘 bounty_unit，没有目击者的辖区不贡献赏金，总额在 bounty_cap 处截断；⑥领取要求该辖区当前赏金大于 0、领取者非空，已领金额参与抵扣，没有新增案件时再次领取报 WANTED_NO_BOUNTY；⑦decay 只按完整衰减周期计算，从上次结算锚点起每满 decay_interval 每个辖区减 decay_step，减到 0 即结案并删除该辖区记录，返回本次移除的热度总量；⑧decay 传入早于锚点的时间报 WANTED_CLOCK_REGRESSION，不消耗半个周期；⑨clear 的罚金为热度乘 fine_per_heat，缴纳足额罚金或距最后事件已满 clear_cooldown 才允许清除，否则报 WANTED_COOLDOWN_ACTIVE，成功时返回实缴金额与移除的热度，免费清除的实缴为 0；⑩records 按辖区名升序给出热度、目击者与最后事件时间，heat 省略辖区时返回该玩家总热度，list_wanted 按总热度降序、同热度按玩家名升序并过滤 min_heat；⑪赏金被领取后热度不能清零，未结案的辖区仍保留基础通缉值；⑫没有目击者的犯罪只增加局部热度，不生成赏金也不向其他辖区传播；跨辖区引渡要先按各辖区上限分别钳制再取最大值，不能先加总再截断。

硬约束：add_heat、witness、decay、clear 共用一把锁，多线程同时上报事件时热度累加不能丢，stats.events 必须等于成功上报次数，同一玩家的最后事件时间只能前进；快照固定为 version、players、stats 三个键，深拷贝，restore 校验版本与结构，缺键或类型不对报 WANTED_SNAPSHOT_INVALID 且现场不动，恢复后热度、目击者、已领赏金与衰减锚点继续可用，重启不能让通缉凭空消失。单玩家辖区数、赏金总额与热度都有硬上限，bounty 与 list_wanted 不得对全量玩家做嵌套扫描。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与重启恢复自行验证；只做本地实现，不引入第三方库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: wanted_heat_ledger
- typeName: WantedHeatLedger
