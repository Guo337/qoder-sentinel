# reference/ —— 上游源码只读副本

本目录存放**第三方开源项目的原始源码副本**，用于开发期对照与许可证留存。
它**不是本项目的代码**，也**不在运行时被导入**。

## 规则

1. **只读**：不要修改这里的任何文件。它们是逐字节副本（可用 SHA256 与上游比对）。
2. **运行时不导入**：`qoder_guard/` 与 `guard/` 的任何代码都不得 `import reference.*`。
   回归探针 `tools/_probe_path_independence.py` 会静态扫描本仓库的绝对路径与依赖，
   任何运行期耦合都属于缺陷。
3. **不复制回主代码**：不要把这里的代码粘进 `qoder_guard/`。若确需移植，
   必须在**目标文件头部**加入上游的版权与许可证声明，并在
   [`../THIRD_PARTY_LICENSES.md`](../THIRD_PARTY_LICENSES.md) 中登记。

## 内容

| 路径 | 来源 | 许可证 | 说明 |
|------|------|--------|------|
| `LICENSE-OpenHands-software-agent-sdk.txt` | [OpenHands/software-agent-sdk](https://github.com/OpenHands/software-agent-sdk) | MIT | 上游许可证全文，逐字节副本 |
| `openhands/*.py` | 同上（`openhands-sdk/openhands/sdk/security/`） | MIT | 8 个源文件逐字副本：`risk.py`、`analyzer.py`、`confirmation_policy.py`、`ensemble.py`、`llm_analyzer.py`、`shell_parser.py`、`_shell_ast.py`、`__init__.py` |

## 为什么留在这里

- **许可证合规**：MIT 要求分发时保留版权声明与许可声明，本目录 + 根目录
  `THIRD_PARTY_LICENSES.md` 共同满足。
- **可追溯**：移植代码的"移植自哪一行"必须能当场核对，而不是靠记忆。

## 与主代码的关系

已移植进主代码的部分（**文件头带 MIT 声明**）：

- `qoder_guard/shell_ast.py` —— 基于上游 `shell_parser.py` / `_shell_ast.py`
- `qoder_guard/risk.py` —— `RiskLevel` 比较运算符移植自上游 `risk.py`

**故意偏离上游**之处（按影响半径而非形状判级）记录在
`../THIRD_PARTY_LICENSES.md` 与 `../tools/_probe_upstream_parity.py`。
