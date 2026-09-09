# 第三方许可证与参考说明

本项目（Qoder 监管层 / Q_explo）在设计与实现过程中**参考**了下列开源项目。
本文件用于如实记录参考来源与其许可证，满足归属要求。

---

## 1. OpenHands software-agent-sdk

- **仓库**：`OpenHands/software-agent-sdk`
- **许可证**：MIT License
- **版权**：Copyright (c) 2026 OpenHands contributors
- **完整许可证文本**：见 [`reference/LICENSE-OpenHands-software-agent-sdk.txt`](reference/LICENSE-OpenHands-software-agent-sdk.txt)
- **参考的源文件**（仅作架构借鉴，存于 `reference/openhands/`）：
  `risk.py`、`analyzer.py`、`confirmation_policy.py`、`ensemble.py`、`shell_parser.py`、`_shell_ast.py`、`llm_analyzer.py`

### 使用方式说明（重要）

本项目对 OpenHands 的使用属于**架构模式借鉴**，具体为：

1. **「风险分析」与「确认策略」分离为两层** 的设计思想
   → 影响 `qoder_guard/risk.py`（分析器）与 `qoder_guard/policy.py`（策略层）的划分
2. **引入 `UNKNOWN` 风险等级** 表达「无法静态判定」，而非默认放行
   → 影响 `qoder_guard/risk.py` 的 `RiskLevel.UNKNOWN` 与 `policy.py` 的保守分支
3. **`opaque`（不可静态求值）标记** 的概念
   → 影响 `qoder_guard/shell_tokens.py` 的 `Token.opaque`

**本项目未整体复制 OpenHands 的源代码。** 上述模块为独立编写：
- 未使用 `pydantic`、`tree_sitter`、`rich`（OpenHands 的依赖），仅用 Python 标准库
- 数据结构、函数签名、命名与实现逻辑均为本项目原创
- 借鉴的仅是**不受版权保护的设计思想**

### 已移植的具体代码（2026-09-08）

`qoder_guard/risk.py` 的 `RiskLevel` 比较运算符为**移植**（非仅借鉴思想），
对应上游 `openhands/sdk/security/risk.py` 的 `_check_comparable` / `__lt__` /
`__gt__` / `__le__` / `__ge__`：

- 原因：`RiskLevel(str, Enum)` 会**静默继承字符串排序**（`HIGH < LOW < MEDIUM`），
  `max()` 会返回 `MEDIUM` 而非 `HIGH`；上游用显式运算符 + `_RISK_ORDER` 解决
- 语义：`LOW < MEDIUM < HIGH`；**与 UNKNOWN 比较抛 `ValueError`**（不可排序）
- 同一处的「破坏性形状」判定（recursive AND force 才算）与上游一致，
  但**结果等级故意不同**，见下方「偏离说明」

### 偏离说明（故意不照抄上游）

上游按**形状**判级（`rm "-r" file` → LOW）；本项目按**影响半径**判级
（`rm "-r" file` → MEDIUM，与 `mv`/`cp -r`/`git clean` 同级）。理由：
`rm -r "$FLAGS" /` 在 `$FLAGS` 为空时等价于 `rm -r /`，判 LOW 会低估风险。
两处偏离已在 `tools/_probe_upstream_parity.py` 中显式标注为 `DEVIATION`。

> 若后续直接复制更多 OpenHands 代码片段，须在**该文件头部**加入 MIT 许可证声明。

---

## 2. tree-sitter / tree-sitter-bash

- **仓库**：`tree-sitter/tree-sitter`、`tree-sitter/tree-sitter-bash`
- **许可证**：MIT
- **状态**：**已作为运行时依赖采用（2026-09-08）**
- **版本**：`tree-sitter>=0.26.0`、`tree-sitter-bash>=0.25.1`（锁定于 `uv.lock`）
- **为什么引入**：命令评分原先拿正则扫原文，看不见语法结构，导致 `(rm -rf /)`、
  `if ...; then rm -rf /; fi`、`FOO=bar rm -rf /` 等**结构性命令被判 LOW**
  （实测 20 条里逃逸 13 条）。tree-sitter 提供真实语法树，可遍历全部
  `command_name` 节点，从根上消掉这一类漏洞。
- **代价实测**：3 个包、Windows 有预编译 wheel（无需编译器）、安装 20 秒、
  hook 启动开销 +20ms（70ms → 93ms）。
- **降级策略**：若 `tree_sitter` 导入失败（例如 `.venv` 被删且无 uv），
  `qoder_guard/shell_ast.py` 的 `AVAILABLE` 置为 `False`，自动退回纯正则模式，
  **监控不中断**，只是安全等级降低。
- **依赖管理**：`uv`（`pyproject.toml` + `uv.lock`）。`.venv/` 不入库，
  `uv.lock` 必须入库。

---

## 3. humanlayer / humanlayer

- **仓库**：`humanlayer/humanlayer`
- **许可证**：Apache License 2.0
- **版权**：Copyright (c) 2024, humanlayer Authors
- **状态**：**仅调研，未参考其代码或架构**

---

## 4. 已评估但**未采用**的项目

| 项目 | 许可证 | 评估结论 |
|---|---|---|
| `idank/bashlex` | **GPL-3.0** | **不可用**。功能合适（真 bash AST，能正确解析 `$(...)`/`<(...)`，优于 `shlex.split`），但 GPL-3.0 是强 copyleft，与本项目宽松许可证不兼容，**不得复制进代码库**，也不宜作为依赖（会对分发施加 GPL 义务） |
| `tree_sitter` + `tree_sitter_bash` | MIT | **已采用（2026-09-08）**，见第 2 节。原先因“零依赖”硬约束而暂缓，该约束已由用户放宽（允许 uv 管理的依赖） |
| `openai/codex` | Apache-2.0 | 代码搜索无结果（查询未命中），未评估 |

## 5. 待确认许可证的项目（仅调研，未使用）

| 项目 | 许可证状态 | 使用情况 |
|---|---|---|
| `disler/claude-code-hooks-mastery` | 未确认 | 仅调研，未使用 |
| `disler/claude-code-hooks-multi-agent-observability` | 未确认 | 仅调研，未使用 |
| `anthropics/claude-code-security-review` | 未确认 | 仅调研，未使用 |

**注意**：以上三个项目在采用前必须**先确认许可证**。未确认前不得复制其任何代码。

---

## 6. 本项目自身依赖

运行时依赖**仅两项**（均为 MIT，由 `uv` 管理）：

| 依赖 | 用途 | 许可证 |
|---|---|---|
| `tree-sitter` | 语法树解析引擎 | MIT |
| `tree-sitter-bash` | bash 语法定义 | MIT |

其余全部使用 Python 3.11 标准库：
`json`、`shlex`、`re`、`dataclasses`、`enum`、`abc`、`pathlib`、`threading`、`subprocess`、`sys`、`os`、`time`、`hashlib`、`sqlite3`、`tempfile`。

**降级保证**：hook 代码在 `tree_sitter` 缺失时仍可运行（退回正则模式），
因此即使 `.venv` 被删除、且 uv 不可用，监控也不会中断。

状态存储使用标准库 `sqlite3`（WAL 日志模式），取代了先前自写的
`qoder_guard/_filelock.py` 文件锁方案；详见 `qoder_guard/_store.py` 的实测对比。

---

*最后更新：2026-09-08（tree-sitter 转为已采用依赖；新增 uv 依赖管理说明）*
