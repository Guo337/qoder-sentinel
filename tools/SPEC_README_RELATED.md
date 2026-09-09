# Qoder 编码任务规格书（README「相关项目」章节）

> 本文件是分派给 Qoder CN CLI 的**任务输入**。执行者请严格遵守，不要自行扩大范围。

## 0. 任务背景

`qoder-sentinel` 是 Qoder CLI 的执行前风险闸门。仓库刚公开，需要新增一节
「相关项目」，说明同类工具的位置与本项目的差异 —— 既是对读者的诚实交代，
也是开源礼仪（给上游/同类项目应有的引用）。

## 1. 硬约束（违反即返工）

| 约束 | 说明 |
|---|---|
| **只改一个文件** | 只允许修改 `README.md`。**禁止**改动任何其他文件 |
| **只做插入** | 在指定锚点处**插入**新章节，不得改写、删除、重排任何既有内容 |
| **编码** | UTF-8 **无 BOM**（README 现有编码就是 UTF-8 无 BOM，必须保持一致） |
| **中文正文** | 新增章节用中文撰写（与 README 其余部分一致） |
| **英文专有名词** | 项目名、语言名、许可证名保持英文原样 |
| **不许执行命令** | 只写文件。不要运行 `python`、`git`、`gh` 等任何命令 |
| **不许编造** | 只能使用本规格书 §3 表格里给出的数据。**不得自行补充任何星标数、日期、功能** |
| **不许改标题层级** | 新章节用 `## 七、` 开头（与现有 `## 六、` 同级） |

## 2. 插入位置

在 `README.md` 中，**文件末尾**（`## 六、许可证与第三方来源` 一节全部内容之后）
追加新章节。文件末尾当前是这段（作为锚点，不要改动它）：

```
`reference/` 目录存放上游源码的**只读逐字副本**（仅用于对照，运行时不导入），
其说明见 [`reference/README.md`](reference/README.md)。
```

在这两行**之后**空一行，然后插入 §3 的内容。

## 3. 要插入的内容（照抄，只允许调整表格列宽对齐）

```markdown
---

## 七、相关项目

同赛道已有若干成熟项目，本项目与它们的关系如下。**数据截至 2026-09-09**，
星标数与许可证均以各仓库主页为准。

### 7.1 同类工具（跨 CLI 通用守卫）

| 项目 | 星标 | 语言 | 许可证 | 与本项目的关系 |
|------|------|------|--------|----------------|
| [cc-safety-net](https://github.com/kenryu42/cc-safety-net) | 1532 | TypeScript | MIT | **最接近**。执行前拦截破坏性 git/文件命令与敏感文件访问，支持 13 个 CLI 适配器，但**不含 Qoder**。其 hook 入口为 `hook --coding-cli`，属多 CLI 适配器架构 |
| [shellfirm](https://github.com/kaplanelad/shellfirm) | 930 | Rust | Apache-2.0 | 100+ 危险模式、8 种 shell（含 PowerShell）、上下文升级、团队策略文件、JSONL 审计，自带 MCP server |
| [claude-code-guardrails](https://github.com/rulebricks/claude-code-guardrails) | 79 | Python | MIT | Claude Code 工具调用的实时护栏 |
| [aport-agent-guardrails](https://github.com/aporthq/aport-agent-guardrails) | 25 | Shell | 自定义 | 执行前授权，覆盖 openclaw/cursor/claude-code/langchain/crewai/n8n，**不含 Qoder** |

### 7.2 Qoder 专属项目

| 项目 | 星标 | 语言 | 许可证 | 与本项目的关系 |
|------|------|------|--------|----------------|
| [anolisa](https://github.com/alibaba/anolisa) | 608 | Rust | Apache-2.0 | **唯一重量级 Qoder 玩家**。其 `src/agent-sec-core/qoder-plugin/` 提供 5 个 hook（命令扫描 / PII 检查 / 提示注入扫描 / Skill 台账 / 可观测性），覆盖 6 类事件。定位是广义 Agent 安全套件，**无风险分级与审批队列**；安装脚本依赖 bash 与自家 `agent-sec-cli`，当前为 Linux 专用 |
| [Oscaner/skills](https://github.com/Oscaner/skills) | 78 | JavaScript | MIT | 含 Qoder PreToolUse 适配器 |
| [openlogos](https://github.com/miniidealab/openlogos) | 72 | TypeScript | Apache-2.0 | 含 PreToolUse 守卫规范与 Qoder 适配器规划 |

### 7.3 本项目的差异

**本项目独有**：

- 四档风险分级（HIGH / MEDIUM / LOW / **UNKNOWN**），基于命令语法结构（tree-sitter）
  而非纯正则匹配
- UNKNOWN 的两层处理：静态降级 + 文件队列交由监督方审批
- 审批队列的**指纹缓存**：同一条命令只询问一次，避免反复打断

**本项目的短板**（相比 cc-safety-net / shellfirm）：

- 仅支持 Windows，仅面向 Qoder CLI
- 无 GUI、无规则库、无团队策略共享，无 MCP 暴露
- 危险模式数量远少于 shellfirm

**边界说明**：本项目聚焦「执行前风险分级 + 审批」，与上述项目在目标上部分重叠
但侧重不同。选择哪个取决于你用哪个 CLI、跑在什么平台。
```

## 4. 交付方式

1. 用编辑工具修改 `README.md`（**只此一个文件**）
2. 完成后**回报**：
   - 修改后的 `README.md` 行数（改前是多少、改后是多少）
   - 新增章节的起始行号
   - 确认：**除末尾追加外，没有任何既有行被修改**（用你的判断，不要跑 git）
   - 任何你认为规格有歧义的地方（先报告，不要自行猜测）

## 5. 明确不要做的事

- ❌ 不要修改 `README.md` 里 `## 六、` 及之前**任何**内容
- ❌ 不要新增星标数、日期、功能描述（只能用 §3 给的数据）
- ❌ 不要改表格为其他格式，不要加 emoji
- ❌ 不要动 `THIRD_PARTY_LICENSES.md`、`pyproject.toml` 或任何 `.py` 文件
- ❌ 不要跑命令、不要 git commit
