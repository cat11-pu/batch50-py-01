# batch50-py-game-a-05

## 题面

限时抢购这场出了几笔对不上的账：库存只剩一件，两个号同时下单都提示成功，仓库发出两件；同一个订单号重复提交，后台扣了两次额度；下单占位超时释放以后，账号的限购额度却没有回来，客服只能手工改；活动结束那一刻还在支付中的订单，有的被判无效，玩家已经付了钱却拿不到货，财务按订单号抽了十笔，库存流水、额度流水和订单状态三份都对不上，对不上的单子越积越多，活动方要求当天给出复算口径。范围是 gsb/batch50-py-game-a-05 的 flash_sale_stock.py，类 FlashSaleStock，维护全局库存、账号限购、下单占位、提交扣减与超时释放。

公开接口：FlashSaleStock(*, total_stock, per_account_limit, hold_ttl)；open_session(session_id, *, now=None)；close_session(*, now=None)；reserve(order_id, account, qty, *, now=None)；commit(order_id, *, now=None)；release(order_id, *, now=None)；expire_reservations(*, now=None)；stock_of、quota_of、order_of；snapshot、restore、stats。所有拒绝统一抛 FlashSaleError(code, detail)。open_session 与 close_session 返回活动记录，含 session_id、total_stock、per_account_limit、hold_ttl、status 与 closed_at；reserve 返回占位记录，含 order_id、account、qty、status、created_at 与 expires_at。

故障与边界：①一场活动只能开一次，重复开回报 FLASH_SESSION_ACTIVE，库存、限购或占位时长为非正数报 FLASH_INVALID_CONFIG；②reserve 要求 qty 为正整数、订单号非空，否则 FLASH_INVALID_REQUEST，失败不得留下半条占位记录；③同一订单号无论账号是否相同都只能提交一次，重复报 FLASH_DUPLICATE_ORDER，已释放或已过期的订单号也不能复用；④占位只冻结库存与额度，commit 才真正扣减，重复 commit 报 FLASH_ALREADY_COMMITTED；⑤库存或账号额度不足分别报 FLASH_INSUFFICIENT_STOCK 与 FLASH_QUOTA_EXCEEDED，两种拒绝都不改动剩余库存与额度；⑥release 把库存与额度还给账号，非占位状态的订单释放报 FLASH_NOT_HELD，已成交额度不回滚；⑦占位到期后由 expire_reservations 统一释放并返回释放数量，释放数量只统计本次真正到期的占位，已过期订单不能再 commit（报 FLASH_NOT_HELD），活动结束后新下单报 FLASH_SESSION_CLOSED；⑧占位超时释放要把该账号的限购额度回滚，已成交的额度不回滚；⑨活动关闭瞬间仍在占位中的订单按提交时间判定有效，不按提交完成时间；⑩未知订单号在 commit、release、order_of 上统一报 FLASH_UNKNOWN_ORDER；⑪快照要保留活动状态、订单占位、已成交数量与每账号额度，restore 非法结构报 FLASH_SNAPSHOT_INVALID 且原状态不变；⑫stats 至少含 sessions、reservations、committed_orders、released_orders、expired_orders、duplicate_orders、quota_refusals、stock_refusals。

硬约束：并发下单不得超卖，库存与额度校验、占位写入必须在同一把锁内完成，超时释放与提交同时发生时订单只能落到一个终态；快照恢复后库存、占位、已成交与活动关闭标记都要还原，且不得与调用方共享可变结构；同一账号的占位与成交量只按有效订单累计，释放后不得重复回补额度或库存，占位与成交的数量始终满足库存恒等式。

验收：python3 -m pytest -q tests 15 条必须全过；不得改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现，不依赖外部服务。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: flash_sale_stock
- typeName: FlashSaleStock
