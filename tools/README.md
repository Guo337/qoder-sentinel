# tools/ —— 观测与回归工具

本目录是**开发期工具**，不参与运行时。分两类：

1. **协议行为核对工具**：Qoder CLI 升级后，官方 hook 协议可能变更。
   重跑这些脚本可确认 `permissionDecision` 三态、阻塞语义、字段名是否仍然一致，
   避免监管层静默失效。
2. **回归测试探针**：见下方「回归测试工具」。

## 前置

需要本地已安装并登录 Qoder CLI。

## 协议核对脚本

| 脚本 | 作用 |
|------|------|
| `parse_events.py` | 解析 `-o stream-json` 输出，打印事件类型与关键内容 |
| `_hook_report.py` | 逐个 hook 报告 `exit_code` 与 stdout/stderr，快速定位 hook 失败（自动嗅探 UTF-16/UTF-8 编码） |
| `_summarize_stream.py` | 每个流事件一行摘要，并转储含 probe/security/warning 的块 |
| `_inspect_l1.py` / `_dump_l1_events.py` / `_extract_l1_warning.py` | Qoder Security L1 警告排查三件套（事件、全量转储、文本提取） |
| `_plugin_audit.py` | 跨 `settings.json` 备份审计插件开关与 `securityScan` 标志 |
| `enable_security_scan.py` | 启用 Qoder Security（默认 dry-run，`--apply` 才写入，自动备份） |
| `_gh.py` | 调 `gh api` 并打印选中字段，规避 PowerShell 参数拆分 |
| `_code_stats.py` | 统计自有/移植代码量与依赖 |
| `_count_rules.py` | 统计 `risk.py` / `sensitive.py` 的规则条数 |
| `_compare_harness.py` | 对比官方 better-harness 与本项目的清单差异 |
| `_probe_project_install.py` | `guard/install_project.py` 的注册契约（dry-run / check / 幂等 / 保留外来 hook / 修复陈旧路径 / BOM / remove / json / 不碰用户配置） | `all checks passed` |

## 用法

```powershell
# 解析一次任务的流式事件，逐条核对 hook 字段
qodercn -p "你的任务" -o stream-json *> out.jsonl
python tools\parse_events.py out.jsonl
```

协议定义以**官方文档**为准：<https://docs.qoder.com/cli/hooks>
（参考页 <https://docs.qoder.com/cli/hooks-reference>）。

## 注意

- 这些脚本**只读**，不修改任何东西

## 回归测试工具

用于验证 `qoder_guard/` 的判定逻辑与状态写入。**改动 guard 后应全跑一遍**，
每个脚本退出码 0 即通过（探针失败会打印 `BAD` 并返回非 0）。

| 脚本 | 作用 | 期望结果 |
|------|------|----------|
| `_verify_behavior.py` | 决策路径端到端行为 | 全 OK |
| `_verify_i18n.py` | 代码文本无中文残留 | 全 OK |
| `_e2e_hook.py` | 以真实子进程跑 `observe_hook.py`（退出码、deny JSON、恶意/原始字节载荷） | `ALL E2E TESTS PASSED` |
| `_probe_debug.py` | 分级回归扫描（分段拆分、UNKNOWN 指纹稳定性） | `0 mismatch(es)` |
| `_probe_whitelist.py` | 只读白名单 vs 重定向/比较/命令替换 | `0 mismatch(es)` |
| `_probe_upstream_parity.py` | 与 OpenHands SDK 官方用例对照分级（含 2 处**故意偏离**） | `full parity` |
| `_probe_rm_shape.py` | `rm` 按标志形状分级（recursive+force 才是 HIGH） | `all cases match` |
| `_probe_structural_escapes.py` | 结构性命令（子 shell / if / for / case / 函数体 / 赋值前缀）不得藏住删除 | `failures=0` |
| `_probe_shell_ast.py` | tree-sitter AST 层契约（嵌套命令发现、opacity、降级路径） | `failures=0` |
| `_probe_bypass_matrix.py` | 变异绕过矩阵：6 类危险意图 × 50 种伪装写法 | `escaped: 0` |
| `_probe_false_positive.py` | 误报矩阵：25 条无害 + 19 条危险必须分清 | `failures=0` |
| `_probe_path_independence.py` | 把项目复制到含空格/中文的路径后跑：无机器专属绝对路径、cwd 无关、三种斜杠写法、状态跟随脚本、**两处注册自检对 DIFFERENT/MISSING/OK 三态判定一致** | `path independence holds` |
| `_probe_concurrency.py` | 4 进程 × 25 次 `review.resolve()` | 100/100 decisions |
| `_probe_audit_concurrency.py` | 4 进程 × 50 次 `audit.append()` | 200/200 records |
| `_probe_sqlite.py` | SQLite 写入原语实测（4/8/16 进程） | `0 failing configuration(s)` |
| `_probe_audit_isolation.py` | 跑全部测试后生产库行数不变 | `all assertions passed` |
| `_probe_sensitive.py` | 敏感数据扫描器单元契约（17 规则、span 合法、去重、脱敏往返、10 误报 / 6 真阳性、ReDoS 与吞吐） | `all checks passed` |
| `_probe_sensitive_hook.py` | 敏感数据接入 hook 的端到端契约（HIGH 拒绝 / observe 放行 / 审计脱敏 / `Write.content` 不拦但脱敏 / 原有危险判定不受影响） | `all checks passed` |
| `_probe_project_install.py` | 项目级安装器契约（11 组 30 项，全部在临时目录内完成） | `all checks passed` |
| `_count_rules.py` | 规则条数统计（`risk.py` 26 条 + `sensitive.py` 17 类） | 正常打印计数 |
| `_compare_harness.py` | 官方 better-harness 清单对比 | 正常打印差异 |
| `_probe_append_mechanism.py` | 历史记录：对比追加写原语（text / oswrite / msvcrt） | 仅 msvcrt 无丢失 |
| `_probe_append_lock.py` | 历史记录：4 种原语 × 4/8/12/16 进程压力测试 | `msvcrt` 行显示 OK |

> `_hook_report.py` 需要传入一个 stream-json 捕获文件，因此**不进入无参回归循环**：
> `python tools\_hook_report.py <capture.json>`

一键跑法：

```powershell
cd qoder-sentinel
uv sync                      # 首次或依赖变更后：建立 .venv 并锁版本
uv run python tools\_probe_structural_escapes.py   # 单跑

# 全量回归（每个脚本退出码 0 即通过）
foreach($f in @("qoder_guard\_store.py","qoder_guard\shell_tokens.py",
  "qoder_guard\policy.py","qoder_guard\review.py","qoder_guard\sensitive.py",
  "guard\verify_setup.py",
  "tools\_verify_behavior.py","tools\_verify_i18n.py","tools\_e2e_hook.py",
  "tools\_probe_debug.py","tools\_probe_whitelist.py",
  "tools\_probe_upstream_parity.py","tools\_probe_rm_shape.py",
  "tools\_probe_structural_escapes.py","tools\_probe_shell_ast.py",
  "tools\_probe_bypass_matrix.py","tools\_probe_false_positive.py",
  "tools\_probe_path_independence.py",
  "tools\_probe_uv_run_hook.py","tools\_probe_sqlite.py",
  "tools\_probe_concurrency.py","tools\_probe_audit_concurrency.py",
  "tools\_probe_audit_isolation.py","tools\_probe_sensitive.py",
  "tools\_probe_sensitive_hook.py","tools\_count_rules.py",
  "tools\_compare_harness.py","tools\_probe_project_install.py")){ uv run python $f *> $null
  Write-Output ("{0,-38} exit={1}" -f $f,$LASTEXITCODE) }
```

> 依赖说明：hook 只需 `tree-sitter` / `tree-sitter-bash`（MIT）。若 `.venv` 被删，
> `uv run` 会自动重建（约 1.3 秒，仅首次）；若 uv 也不可用，可用系统 Python
> 跑回归，guard 会退回纯正则模式（`_probe_shell_ast.py` 会报 `grammar unavailable`）。

`_probe_append_mechanism.py` 与 `_probe_append_lock.py` 保留为历史记录：
它们证明了裸 `open(path, "a")` 在 Windows 下会丢写，是改用 SQLite 的依据。
`SPEC_REVIEW_CONCURRENCY.md` 是并发修复的设计记录（含原语实测对比与一条
被推翻的原始假设），不是可执行脚本。

