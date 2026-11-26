# batch50-py-game-a-02-p5

## 题面

卡牌服连出对账问题：同一套牌两次重放抽到的顺序不同，申诉无法复核；起手换牌后手里多出一张、牌库少一张；有对局在牌库见底时把弃牌堆洗回去。范围是 gsb/batch50-py-game-a-02-p5 的 deck_zone_manager.py，类 DeckZoneManager，管牌库、手牌、弃牌堆、放逐区与战场流转，按对局种子与洗牌序号派生顺序。

公开接口：load_deck(cards)、draw(count=1)、discard(card_id)、exile(card_id)、deploy(card_id)、shuffle(reason)、mulligan(card_ids)、cards_in(zone)、describe(card_id)、snapshot、restore、stats，拒绝抛 DeckError(code, detail)。

故障与边界：①load_deck 要求非空且 id 唯一，重复或空值报 DECK_INVALID_LOAD，二次加载报 DECK_ALREADY_LOADED；②draw 从顶部按序取牌入手牌，返回值同手牌序；③count 非正报 DECK_INVALID_REQUEST；手牌超上限报 DECK_HAND_LIMIT 且不移动；④牌库为空仍抽牌按疲劳累计报 DECK_EMPTY_DRAW，不得洗回弃牌堆；⑤discard/deploy 只认手牌，否则 DECK_NOT_IN_HAND；exile 可移出手牌或牌库；⑥洗牌由种子与序号派生，同种子同序号一致；已公开置顶的牌洗后仍留顶位；⑦mulligan 把指定手牌放回牌库、重洗后补抽同数量，换牌数量影响后续洗牌序号；⑧cards_in/describe 按区内位置返回，牌库未公开的 visible 为假；⑨并发抽牌串行、不重复不丢失；⑩snapshot 深拷贝，restore 非法报 DECK_SNAPSHOT_INVALID。

硬约束：抽牌、弃牌、洗牌、换牌同锁串行，并发无重复实例；快照恢复后各区顺序、洗牌序号与统计都在、不共享结构。stats 含 loaded、drawn、discarded、shuffles、fatigue。

验收：python3 -m pytest -q tests 15 条全过；不得改测试、跳过或写死；并发重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: deck_zone_manager
- typeName: DeckZoneManager
