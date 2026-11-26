# batch50-py-game-b-09-p5

## 题面

本地化排版这批界面返工最多：带组合符号的字符在回退时被拆到两种字体，屏幕上出现断开的音符和双份宽度；限行两行的公告在省略号之后，后面的强制换行整体上移，把下一段挤进了页脚；生僻字在所有字体里都没有，程序直接抛错退出，整屏文字消失；字体热替换后旧布局还在用老字宽，回滚一次又得清一遍缓存。范围是 gsb/batch50-py-game-b-09-p5 的 text_run_shaper.py，类 TextRunShaper，把带样式和语言标记的文本切成字形运行，按字体回退链为每个字素簇选择可用字体，处理字距、连字开关、强制换行与尾行省略。

公开接口：TextRunShaper(*, max_runs=64, max_cache_entries=128)；register_font(font_id, *, glyphs, version=1, fallbacks=())；rollback_font(font_id)；font_info(font_id)；resolve_fallback(font_id, text)；shape_run(text, *, font_id, size=16.0, features=())；break_lines(text, *, font_id, size=16.0, max_width, max_lines=0)；layout(text, *, font_id, size=16.0, max_width, max_lines=0, features=())；cache_key(text, *, font_id, size, max_width, max_lines=0, features=())；invalidate_cache(font_id=None)；fonts()；snapshot()；restore(state)；stats()。所有拒绝统一抛 TextShapeError(code, detail)。

故障与边界：①字体号不得为空，glyphs 为非空映射且每个 advance 为正，version 为正整数，fallbacks 必须是已注册字体，重复注册同版本报 TEXT_FONT_VERSION_CONFLICT，未知字体报 TEXT_UNKNOWN_FONT，register_font 返回注册后的版本号，fonts 按编号升序返回，font_info 含 font_id、version、glyph_count、fallbacks，fallbacks 以元组返回；②字号为正、max_width 为正、max_lines 非负，违规报 TEXT_INVALID_REQUEST；③字宽等于 advance 乘字号，shape_run 返回 clusters、fonts、advances、width，clusters、fonts、advances 都以元组返回，features 按给定顺序原样保存并参与缓存键，空文本按零个簇、零宽度处理；④resolve_fallback 按字素簇逐簇在回退链里找第一个覆盖全部码点的字体，返回 chains 与 missing 元组；⑤组合字符与变体选择符必须作为一个字素簇整体回退，不能中途换字体导致拆字；⑥break_lines 优先在空格处折行，单行超宽的长词按字素簇切开，强制换行符必须原样保留成空行，break_lines 与 layout 的 lines 每项含 text、width、ellipsis；⑦max_lines 大于零且内容超行时，最后一行按可用宽度减去省略号宽度截断并标 ellipsis，省略号宽度按同一字体的 advance 乘字号，省略号本身占一个字形位；⑧尾行省略后剩余的强制换行要保留行数占位，不能把后续段落整体上移；⑨回退链全部缺失该字符时用缺字字形占位，但布局结果必须保留原字素簇边界；⑩layout 按参数缓存，命中带 cached 为真，结果含 text、font_id、size、max_width、max_lines、lines、width、cache_key，lines 每项含 text、width、ellipsis，invalidate_cache 返回清掉的条目数，不传字体号清全部；⑪字体热替换要作废旧布局缓存但保留上一版本以便 rollback_font 回滚，rollback_font 返回恢复的版本号，未知字体报 TEXT_UNKNOWN_FONT；⑫snapshot 返回 {"schema","fonts","cache","stats"} 深拷贝，restore 结构非法报 TEXT_SNAPSHOT_INVALID 且原状态不变，stats 至少含 fonts、font_versions、layouts、cache_hits、cache_invalidations。

硬约束：同一文本同一参数并发排版只允许真正计算一次，其余命中缓存且行结果一致；重启恢复后字体版本、回退链与布局缓存都要在，且不与调用方共享结构；运行数、缓存条目与行数都有硬顶，热替换与回滚不得让旧缓存复活。

验收：python3 -m pytest -q tests 的 15 条用例必须全部通过；不得改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: text_run_shaper
- typeName: TextRunShaper
