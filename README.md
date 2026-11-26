# batch50-py-safety-c-26

## 题面

客服与安全团队本周并单反映邮件魔法链接登录不可用：有用户连点两次链接后页面报系统错误，刷新又说链接已失效；有用户换了手机打开链接直接被拒，想重试却没有入口；运营批量重发时旧链接有时还能用、有时又被提前作废；还有客户反馈平台重启后已兑换的链接又回到待用状态，存在被重放的风险。范围是 gsb/batch50-py-safety-c-26 下的 magic_link_issuer.py，类名 MagicLinkIssuer，负责按邮箱签发一次性登录链接、绑定发起设备并裁决兑换。

公开接口：MagicLinkIssuer(*, max_active_per_email=5, resend_policy="keep", default_ttl=900, min_issue_interval=0)；issue(email, *, device_fingerprint, purpose="login", ttl=None, now=None) 返回 LinkTicket（含 token_id、email、purpose、device_fingerprint、issued_at、expires_at、state）；redeem(token_id, *, device_fingerprint, now=None) 与 confirm(token_id, *, device_fingerprint, now=None) 返回 RedeemResult（含 status、token_id、email、purpose、requires_confirmation、redeemed_at）；invalidate(token_id)、invalidate_all(email)、status(token_id)、active_links(email)、purge_expired()、snapshot()、restore(state)、stats()。拒绝时抛 MagicLinkError(code, detail)。

故障与边界：①issue 对邮箱去首尾空白并转小写，token_id 为 ml_ 加 16 位小写十六进制，expires_at 为 now 加 ttl 秒、带 +00:00 的 UTC 字符串，ticket 状态为 pending。②邮箱缺 @、本地部分或域名部分为空抛 MAGIC_LINK_INVALID_EMAIL；purpose 为空或非字符串抛 MAGIC_LINK_BAD_PURPOSE。③ttl 只接受 1 到 86400 的整数，越界抛 MAGIC_LINK_BAD_TTL。④同一邮箱两次签发间隔小于 min_issue_interval 时抛 MAGIC_LINK_RATE_LIMITED，且不占用未消费额度。⑤同一邮箱未消费且未过期的链接达到 max_active_per_email 时抛 MAGIC_LINK_TOO_MANY_ACTIVE，兑换任意一条后可继续签发。⑥redeem 在设备指纹与签发时一致时消费令牌，返回 status="redeemed"、requires_confirmation=False 与 redeemed_at；同一令牌再次兑换返回 status="consumed" 并保留首次兑换时间，不抛异常。⑦令牌未知抛 MAGIC_LINK_UNKNOWN，已过期抛 MAGIC_LINK_EXPIRED 且不改状态，已撤销抛 MAGIC_LINK_REVOKED；过期清理由 purge_expired 完成，把待用链接置为 expired 并返回条数。⑧设备指纹不一致时 redeem 不消费令牌，返回 status="confirmation_required"、requires_confirmation=True，status 的 pending_device 记录本次设备；confirm 只接受与 pending_device 相同的指纹，成功后按当前时间记为已兑换，不一致抛 MAGIC_LINK_DEVICE_MISMATCH，没有待确认记录抛 MAGIC_LINK_NO_PENDING，已兑换再确认抛 MAGIC_LINK_CONSUMED。⑨resend_policy="revoke" 时同邮箱同用途重发要把旧待用链接置为 revoked；"keep" 时旧链接必须继续可用，不得被新签发动作误伤。⑩同一令牌被多个终端同时兑换时只能成功一次，其余请求返回已消费结果，首次兑换时间不得被覆盖。⑪invalidate 只撤销待用链接并返回布尔值；invalidate_all 撤销该邮箱全部待用链接并返回条数；active_links 仅列未过期待用令牌，按 token_id 升序；status 返回 token_id、email、purpose、state、expires_at 与 pending_device。⑫快照含 version、links、counters、stats 四个顶层键且与活动状态完全脱钩；恢复非法结构抛 MAGIC_LINK_SNAPSHOT_INVALID 且不得改动现有数据。stats 返回 issued、redeemed、consumed、revoked、expired、rate_limited，分别在签发成功、兑换成功、重复兑换、撤销、过期清理、限流拒绝时累加。

硬约束：同一邮箱的签发与同一令牌的兑换、确认必须串行，额度判断、状态写入与计数之间不得插入其它变更；重启或快照恢复后已消费、已撤销、已过期的状态与首次兑换时间必须原样回来，待用令牌按原签发时间计算剩余有效期，不得重新计时。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: magic_link_issuer
- typeName: MagicLinkIssuer
