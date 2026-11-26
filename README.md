# batch50-py-game-a-07-p5

## 题面

上周末的跨区活动把天气系统推到了风口浪尖，运营和玩家各报了一串问题。活动方在港口挂了四小时暴雨，活动结束后港口直接变成晴天并锁死到下一个自然周期，而按原种子推下去本该正好轮到小雨；另一路反馈说，某个区域两次切换的间隔不到过渡时长时，画面里的雨量会瞬间跳满，中间那段混合过程整段丢失；还有玩家从客户端抓到了下一时段的活动天气，提前知道官方要在哪里放雾，活动组怀疑预报接口把未公开的覆盖泄露了出去。范围是 gsb/batch50-py-game-a-07-p5 的 weather_cycle_director.py，类 WeatherCycleDirector，负责区域登记、时间推进、未来时段预报，以及活动与管理员覆盖。

公开接口：WeatherCycleDirector(*, max_regions=24, max_forecast=6, transition_ticks=4, seed=7, states=None, durations=None)；register_region(region_id, *, seed=None, state=None, remaining=None)、advance(ticks=1)、current(region_id)、transition_state(region_id)、forecast(region_id, *, slots=None)、override(region_id, state, *, priority=0, source="event", duration=None)、clear_override(region_id, *, priority=None, source=None)、active_overrides(region_id)、list_regions()、snapshot()、restore(state)、stats()。拒绝一律抛 WeatherError(code, detail)。

故障与边界：①默认状态序列为 clear、cloudy、rain、storm，各自的持续时长取 durations，注册时省略 remaining 就取该状态的时长；②区域编号去空白后不得为空、不得重复，超出 max_regions 报 WEATHER_CAPACITY_EXCEEDED 且不新增；③状态不在序列内、remaining 非正整数、seed 非整数、ticks 非正整数一律报 WEATHER_INVALID_REQUEST；④advance 按服务器 tick 单调累加，返回本次发生的自然切换事件，事件带切换发生的绝对 tick、区域、原状态与新状态，未用完的 tick 要在新状态上继续推进；⑤状态切换后进入过渡，transition_ticks 内 blend 从 0 走到 1，超过即固定为 1，transition_state 给出上一状态、当前状态、已过渡 tick 与总时长；⑥预报从当前自然状态按同一套推演展开若干时段，只读不写入，连续两次调用结果一致，slots 省略取 3，超过 max_forecast 或小于 1 报参数错误；⑦覆盖按 priority 高者生效，同优先级取后加入的一条，current 的 source 指向生效层，active_overrides 按优先级降序、同级按加入顺序倒序返回；⑧clear_override 可按 priority 或 source 精确移除，一条都没命中报 WEATHER_OVERRIDE_EMPTY；⑨带 duration 的覆盖每推进一个 tick 递减，减到 0 自动失效并计入 stats.expired；⑩覆盖解除后要回到原种子推演出的状态，不能从解除时刻重新随机；⑪连续两次切换间隔小于过渡时长时，新过渡要从当前混合值起步，不能跳回 0；⑫预报只反映自然推演，不暴露未公开的活动覆盖，但已生效的覆盖必须体现在 current 里。

硬约束：register_region 与 advance 共用一把锁，多线程同时推进时 ticks 总数必须等于成功调用之和，剩余时长与切换事件不能丢也不能重；快照固定为 version、tick、regions、stats 四个键，深拷贝，restore 校验版本与结构，缺键或类型不对报 WEATHER_SNAPSHOT_INVALID 且现场不动，恢复后 tick、剩余时长、覆盖栈与统计继续可用；区域数量、预报长度与每区覆盖层数都有上限，单次 advance 不得反复整表扫描。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与重启恢复自行验证；只做本地实现，不引入第三方库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: weather_cycle_director
- typeName: WeatherCycleDirector
