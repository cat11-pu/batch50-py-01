# batch50-py-safety-a-04

## 题面

周一早上网关报障：三个 SP 的登录回跳里，部分用户拿到的断言是别人的，另有一部分一直停在处理中；运维翻日志发现同一个 artifact 被两个 SP 各解析了一次，其中一条断言落到错误租户，用户登录后能看到别人的资料，后端 artisan 服务在高峰期又大量超时。范围是 gsb/batch50-py-safety-a-04 的 saml_artifact_resolver.py，类 SamlArtifactResolver，负责登记 artifact 与签发 IdP、SP entityID 的绑定，经后端回取断言、核对 InResponseTo 与签名后交付；现在这些入口一调用就抛 NotImplementedError，线上等同于功能缺失。

公开接口：SamlArtifactResolver(*, max_pending_per_tenant=4, artifact_ttl=120)；register_sp(entity_id, tenant, now)、sp_record(entity_id)、set_backend(fetcher)、issue(entity_id, subject, attributes=None, idp_entity_id="idp-1", ttl=None, now=None)、resolve(artifact, entity_id, now)、revoke(artifact)、artifact_state(artifact)、pending_for(entity_id)、expire(now)、snapshot()、restore(state)、stats()。拒绝一律抛 SamlArtifactError(code, detail)。后端 fetcher 形如 fetcher(artifact, entity_id)，成功时返回 BackendAssertion(assertion, in_response_to, signature_valid, subject, attributes)，超过等待时间就抛 TimeoutError。

故障与边界：①artifact 只能成功解析一次，第二次报 SAML_ARTIFACT_CONSUMED，且不得再次触发后端回取；②artifact 与签发时登记的 SP entityID 绑定，被拿到另一个 SP entityID 上解析必须拒绝，不能只验签名；③后端返回的 InResponseTo 与登记值不一致时整条作废，之后对同一 artifact 的解析一律按已作废处理；④后端回取超时返回可重试错误但不得释放 artifact，换好后端后重试仍应成功，超时计数单独记；⑤签名无效同样整条作废，后续解析报 SAML_ARTIFACT_REJECTED，不得因为重试变成成功；⑥entity_id 或 tenant 为空白、subject 为空白都报 SAML_INVALID_REQUEST，未登记 SP 报 SAML_UNKNOWN_SP，未登记 artifact 报 SAML_UNKNOWN_ARTIFACT，artifact 以 AA- 前缀生成且不可预测，InResponseTo 至少 8 个字符且每次不同；⑦expire 把到期的 pending 项记为过期并计数，解析撞上过期项报 SAML_ARTIFACT_EXPIRED；⑧每个租户的未决 artifact 条数有硬上限，超出报 SAML_CAPACITY_EXCEEDED，过期或解析完成立即释放额度；⑨Assertion 的 assertion 与 attributes 取自后端返回，解析中的并发请求要等待同一结果而不是重复回取，后端只允许被调用一次，等待方拿到的断言必须与首个一致，否则高峰期一次超时会拖出成倍的重复回取；⑩revoke 只对 pending 生效，重复撤销返回 False，撤销未登记 artifact 报 SAML_UNKNOWN_ARTIFACT；⑪pending_for 只列该 SP 的未决 artifact，按字符串升序返回元组；⑫快照要带 SP 登记、artifact 状态与计数，重启后未过期的 artifact 仍能正常解析，已解析的不能复活，恢复后 pending_for 的排序与计数也要保持不变。

硬约束：同一 artifact 的并发解析必须在同一把锁里判定后只放一个线程去回取，其余线程等结果，后端调用次数与 resolved 计数都不能随并发数增长；后端超时后状态必须留在 pending，不能写成失败终态，等待方超时也只能保持 pending 等下一次重试；快照固定含 version、sps、artifacts、stats 四个键，是深拷贝，restore 校验结构，缺键或类型不对报 SAML_SNAPSHOT_INVALID 且原状态不被改动；按租户的容量上限是硬顶，超出当场拒绝。stats 至少含 issued、resolved、rejected、expired、revoked、timeouts、backend_calls。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: saml_artifact_resolver
- typeName: SamlArtifactResolver
