# batch50-py-safety-b-06

## 题面

无线控制器这周连着报障：会议室终端在 SAE 认证时反复排队，待认证表几分钟就被填满，正常终端挤不进去；同一台终端断线重连后，控制器给的配对结果和上次对不上；还有终端根本没协商管理帧保护，就完成了关联并拿到了地址。安全组要求把 commit 洪泛、配对错乱和降级关联三件事一起收口。值班同事对照抓包发现，部分终端把 confirm 当成重试反复提交，配对表里出现多份同源记录，排障时无法判断哪一条才是最终结果。范围是 gsb/batch50-py-safety-b-06 的 sae_commit_warden.py，类 SaeCommitWarden，负责每个对端的 commit/confirm 配对、反 clogging 令牌签发核销，以及关联阶段的管理帧保护判定。

公开接口：SaeCommitWarden(*, commit_threshold=3, token_ttl=30, handshake_ttl=120, max_pending=256, transition_mode=False)；on_commit(mac, scalar, token=None, now=None)；on_confirm(mac, send_confirm, now=None)；issue_token(mac, now=None)；authorize_assoc(mac, pmf_negotiated, wpa2_client=False)；handshake_state(mac)；purge_expired(now=None)；pending_peers()；snapshot()；restore(state)；stats()。handshake_state 返回 pending、confirmed 或 unknown。任何拒绝都抛 SaeError(code, detail)。

故障与边界：①同一 MAC 前 commit_threshold 次不带令牌的 commit 返回 accepted，额度用完后返回 token_required 且不建立握手，confirm 成功不重置额度。②令牌绑定 MAC 且只能核销一次，重复使用报 SAE_TOKEN_INVALID；令牌由控制器签发，终端必须在下一帧带回，过期或伪造都按无效处理，带令牌提交一律先校验，不能因为有免令牌额度就跳过。③拿 A 的令牌给 B 用同样报 SAE_TOKEN_INVALID，且不得消耗 A 的令牌；这类串用要单独计拒绝次数，便于定位刷单来源。④同一 MAC 重复提交同一 scalar 视为重发，返回 duplicate，握手编号与计数都不变。⑤同一 MAC 换 scalar 重发要按新握手处理，旧配对作废，不能因为已有待确认握手就静默丢弃；替换后握手编号递增，后续 confirm 只认最新一条。⑥send_confirm 必须等于 commit scalar 加一，不符报 SAE_STATE_CONFLICT 并丢弃该握手。⑦没有待确认握手时收到 confirm 报 SAE_UNKNOWN_PEER；握手超过 handshake_ttl 由 purge_expired 回收并计数，之后状态为 unknown，回收只清理待确认记录，已确认会话不受影响。⑧待认证表达到 max_pending 时新 MAC 的 commit 报 SAE_CAPACITY_EXCEEDED，已有对端不受影响；容量判定在建立握手之前完成，失败不得留下半条记录。⑨PMF 判定先于握手状态，未协商时 authorize_assoc 报 SAE_PMF_REQUIRED；握手未确认就申请关联报 SAE_STATE_CONFLICT。⑩过渡模式只放行明确声明为 WPA2 的客户端，返回未受保护，并且不得把已经关联会话的管理帧保护一起关掉，过渡模式只是临时兼容手段，不能成为长期豁免。⑪反 clogging 令牌过期后终端再次提交，必须重新签发令牌，不能沿用过期令牌放行。⑫空 MAC、非整数 scalar 报 SAE_INVALID_REQUEST；快照含 version、peers、tokens、stats 四个顶层键并深拷贝，非法结构报 SAE_SNAPSHOT_INVALID 且原状态不变。

硬约束：同一 MAC 的并发提交必须串行，令牌至多核销一次；进程重启后未完成握手一律作废，已确认会话与统计保留；待认证表与令牌表都设硬上限。stats 返回 commits、duplicates、tokens_issued、tokens_consumed、token_rejections、confirms、confirm_failures、pmf_denied、purged。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: sae_commit_warden
- typeName: SaeCommitWarden
