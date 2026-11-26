# batch50-py-safety-c-02

## 题面

设备管理代理这两个月连出升级事故：一批路由器刷完固件卡在重启循环，回滚到旧版本又自动被推回坏版本；还有一台在写入途中掉电，引导器却把只写了一半的槽位标成可启动，整机变砖返修。售后翻日志才发现，供应商把同版本号的胶囊重发过一次，内容其实改过，代理按版本号相同直接跳过了校验；另一个现场的运维把胶囊丢进存放目录后机器重启，新进程从零开始重写，把已经写完的大部分内容又覆盖了一遍。范围是 gsb/batch50-py-safety-c-02 的 firmware_capsule_stager.py，类 FirmwareCapsuleStager，负责胶囊校验、A/B 槽位写入、断点续写和引导器切换。初始活动槽为 A、版本 1，min_version 也从 1 起算。现场的要求是：任何一步失败都不能让设备失去可用槽位，也不能把没验证过的胶囊交给引导器；写入进度必须落盘，不能只留在内存里等下一次重启再猜。

公开接口：FirmwareCapsuleStager(storage_dir, *, model, allowed_models=(), trusted_keys=None, chunk_size=32, max_payload_bytes=4096)、add_trusted_key(key_id, secret)、revoke_trusted_key(key_id)、begin_stage(*, capsule_id, model, version, payload, key_id, signature)、append_chunk(capsule_id, data)、finish_stage(capsule_id)、stage(...)、verify(capsule_id)、commit(capsule_id=None)、rollback()、resume()、capsules()、status()、stats()。签名口径是 HMAC-SHA256，被签内容为"型号:版本:载荷 sha256 十六进制"，密钥按 key_id 登记。胶囊状态取 writing、staged、committed，capsules() 按版本升序；begin_stage、append_chunk、finish_stage 与 stage 返回 StageReport(capsule_id, slot, state, written, total, digest, already_staged)，verify 返回 VerificationReport(capsule_id, valid, code, digest, bytes_checked)，commit 与 rollback 返回 TransitionReport(active, previous, version, idempotent)，capsules() 的元素是 CapsuleInfo(capsule_id, version, slot, path, state, written, verified, digest)。status() 给出 model、active、min_version、slots、capsules，slots 下每个槽给出 state、version、digest、written、path；stats() 固定给出 staged、verified、committed、rolled_back、rejected、resumed。拒绝统一抛 FirmwareStagerError(code)。

故障与边界：①型号不在白名单报 FIRMWARE_MODEL_NOT_ALLOWED，参数不合法报 FIRMWARE_INVALID_REQUEST；②key_id 未登记报 FIRMWARE_KEY_UNKNOWN，签名比对不上报 FIRMWARE_SIGNATURE_INVALID；③载荷超过 max_payload_bytes 报 FIRMWARE_PAYLOAD_TOO_LARGE；④版本低于已记录最小版本报 FIRMWARE_VERSION_ROLLBACK；⑤新胶囊只能落在非活动且空闲槽位，无空槽报 FIRMWARE_NO_FREE_SLOT，写入按 chunk 追加并持久化已写字节数；⑥append_chunk 超出总长报 FIRMWARE_STAGE_OVERFLOW，没写满就 finish 报 FIRMWARE_STAGE_INCOMPLETE；⑦verify 必须重新读槽位文件重算整段 sha256，不能只信内存里缓存的摘要，不符返回 valid=False、code 为 FIRMWARE_CHECKSUM_MISMATCH 且不改槽位状态；⑧commit 只接受已验证胶囊，否则 FIRMWARE_NOT_VERIFIED，成功后活动槽切换、previous 记旧槽、min_version 抬到新版本；⑨commit 重复调用返回 idempotent=True，活动槽不再变、committed 计数不涨；⑩rollback 回到上次提交前的槽位，没有目标报 FIRMWARE_NO_ROLLBACK_TARGET，重复 rollback 返回 idempotent=True；⑪同版本号但内容不同的胶囊重复下发必须拒绝，不能因为版本号相同就当已暂存跳过；⑫回滚到旧槽位后 min_version 不得跟着回退，否则可被反复降级。

硬约束：写入进度、槽位状态、胶囊摘要与六个计数器全部持久化，掉电后新进程 resume() 必须从断点续写、不重复覆盖已写字节、校验通过并封口；同一胶囊的 begin、append、finish 与 commit 必须串行化，commit 与 rollback 的槽位切换在锁内一次完成，重复调用幂等，并发下不得出现两个活动槽或计数重记。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；掉电与重启场景自行构造验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch50-py-safety-c-02
- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: firmware_capsule_stager
- typeName: FirmwareCapsuleStager
- topic: 固件胶囊暂存：A/B 槽位、版本单调防回滚与断电续写
