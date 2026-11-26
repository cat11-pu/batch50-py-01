# batch50-py-safety-d-18

## 题面

富文本入口这周出事：作者在正文里塞了未闭合标签，整页排版被带歪；评论区一条大小写混写的链接点开就执行脚本；同一段内容净化两次输出居然不一样，缓存里存的还是旧策略的结果。范围是 gsb/batch50-py-safety-d-18 的 html_sanitize_gate.py，类 HtmlSanitizeGate，负责按版本化允许列表改写富文本并给出可复现的输出。

公开接口：HtmlSanitizeGate(*, max_length=4096, max_depth=12)；sanitize(html, *, tenant="default")、validate_policy(*, allowed_tags, allowed_attributes, allowed_protocols)、reload_policy(同前)、explain(html, *, tenant="default")、status()、stats()、reset_stats()、set_limits(*, max_length=None, max_depth=None)、snapshot()、restore(state)；异常统一抛 SanitizeError(code, detail)。

故障与边界：①输出统一小写：标签名与属性名都转小写，属性按名称字典序，值用双引号且只把 & " < > 转成实体；②空元素 br 输出为 <br/>，其余允许标签成对输出，文本节点只转义 & < >；③不在允许列表的标签丢掉标签本身、保留其内容，script 与 style 连内容整段丢弃；④注释、条件注释与处理指令一律丢弃；⑤href 与 src 只放行 http、https、mailto 三个协议与相对路径，协议判定用解码后的小写值，前后空白先裁掉，不合规的属性直接去掉；⑥同一元素上同名属性只保留最先出现的那个并把重复数加一；⑦未闭合的 p 与 li 遇到同名新标签时隐式闭合前一个，输入结束时按逆序补齐闭合，错误嵌套按就近原则收口；⑧输出字符数超过 max_length 抛 SANITIZE_TOO_LARGE，嵌套层数超过 max_depth 时该层标签丢弃但文本保留；⑨净化结果再净化一次必须逐字节一致；⑩策略热加载后版本号加一、对后续请求原子生效，进行中的请求按进入时版本完成；⑪validate_policy 拒绝 script、style 与非白名单协议，抛 SANITIZE_POLICY_INVALID；⑫浏览器重解析后结构会变的变异型负载，净化后要再做一次重解析校验而不是只做字符串替换；同一属性名以大小写或实体编码重复出现时，去重必须按解析后的名字而不是原始文本；策略删除某个标签后，已缓存的历史净化结果不得继续复用。

sanitize 返回 policy_version、html、dropped_tags、dropped_attributes、duplicate_attributes；explain 按出现顺序返回原因码列表，取值只有 tag_not_allowed、attribute_not_allowed、protocol_not_allowed、comment、duplicate_attribute、depth_exceeded，且 explain 不计入统计。stats 返回 sanitized、dropped_tags、dropped_attributes、duplicates、oversized 五个计数；status 返回 version、allowed_tags、allowed_attributes、allowed_protocols、max_length、max_depth。文本里的换行与连续空白原样保留，不做压缩；tenant 只用于统计归属，不影响允许列表。同一元素上出现多个问题要按出现顺序全部列出；策略版本只增不减，快照恢复后的版本号必须与快照记录一致。

硬约束：sanitize 与 reload_policy 共用一把 threading.RLock 保护策略切换，读策略与写统计必须原子，并发净化不得读到半更新的允许列表；snapshot 返回 version、policy、stats、reloads 四个键且为深拷贝，其中 policy 是含 allowed_tags、allowed_attributes、allowed_protocols 的字典，restore 遇缺键或类型不符抛 SANITIZE_SNAPSHOT_INVALID 且不改动现有策略。

验收：`python3 -m pytest -q tests` 15 条必须全过；不得改测试、跳过、按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: html_sanitize_gate
- typeName: HtmlSanitizeGate
- file: html_sanitize_gate.py
