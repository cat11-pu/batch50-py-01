# batch50-py-safety-d-14

## 题面

邮件网关这周拦下一批仿冒登录页：看着像银行官网的域名其实用西里尔字母拼成；另一个短链跳两次落到品牌变体；还有人把合作方域名塞进子域，想绕过允许清单。范围是 gsb/batch50-py-safety-d-14 的 homograph_url_guard.py，类 HomographUrlGuard。

接口：HomographUrlGuard(*, brands, public_suffixes, max_redirects, report_threshold)；analyze(url, *, redirects, now)；allowlist(domain, *, ttl, now)；is_allowlisted(host, *, now)；feedback(url, *, label, now)；sweep(urls, *, now)；registrable_domain(host)；拒绝抛 UrlGuardError(code, detail)。

边界：①主机小写去尾点去端口，Punycode 与 Unicode 互转后 NFKC。②混合脚本主机名直接高风险。③相似度按可注册域标签算，公共后缀不入编辑距离。④编辑距离、键盘相邻、替换表综合打分，无候选相似度 0。⑤userinfo 的 @ 与反斜杠按浏览器实际解析归一。⑥多级子域按公共后缀表（含 co.uk、com.cn）归到可注册域。⑦允许清单按注册域精确匹配并带到期，仿冒成子域不命中。⑧Punycode 后与品牌 ASCII 相同的形似字符靠原始脚本信息判出。⑨跳转链含原始 URL 并逐跳取最严，超 max_redirects 抛 REDIRECT_LIMIT。⑩无效 URL 抛 INVALID_URL，批量跳过计数继续。⑪同一注册域 3 条钓鱼反馈后默认高风险，非法 label 抛 FEEDBACK_INVALID。⑫品牌表变更递增版本并使缓存失效，快照深拷贝品牌、允许清单与反馈，非法 SNAPSHOT_INVALID。

硬约束：缓存与反馈表在 RLock 内互斥，允许清单变更清缓存；stats 含 analyzed、invalid、cached。

验收：`python3 -m pytest -q tests` 十五条全过；不改测试、不跳过、不写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- module: homograph_url_guard
- typeName: HomographUrlGuard
