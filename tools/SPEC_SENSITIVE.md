# Qoder 编码任务规格书（敏感数据扫描模块）

> 本文件是分派给 Qoder CN CLI 的**任务输入**。执行者请严格遵守，不要自行扩大范围。

## 0. 项目背景（一句话）

`qoder-sentinel` 是 **Qoder CLI 的监管层（guard）**：通过 hook 观测/拦截 Qoder 执行的工具调用，
做风险分级与审计。本次任务新增「敏感数据扫描」能力，用于在工具调用的输入/输出里识别
凭据与个人隐私信息。

## 1. 硬约束（违反即返工）

| 约束 | 说明 |
|---|---|
| **零第三方依赖** | 只许用 Python 标准库（`re` / `dataclasses` / `typing`）。禁止 import 任何第三方包 |
| **Python 版本** | 3.11（可用 `X \| None`、`list[str]`、`tuple[Hit, ...]`） |
| **平台** | 代码必须跨平台（Windows + POSIX），不得出现平台专有调用 |
| **文件编码** | **UTF-8 无 BOM** |
| **代码文本一律英文** | 注释、docstring、字符串字面量**全部英文**。禁止在 `.py` 里出现任何中日韩字符 |
| **不许执行命令** | 只写文件。不要运行 `python`、`pip`、`git`、`pytest` 等任何命令 |
| **不许改已有文件** | 只创建下面指定的**新文件**。特别地：**绝对不要修改** `qoder_guard/hooks.py`、`qoder_guard/risk.py`、`qoder_guard/policy.py` |
| **文件头** | 首行 docstring（英文），紧跟 `from __future__ import annotations` |

## 2. 交付物：`qoder_guard/sensitive.py`

### 2.1 数据结构（名字与字段必须完全一致）

```python
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

@dataclass(frozen=True, slots=True)
class SensitiveHit:
    kind: str          # machine-readable id, e.g. "github_token"
    severity: str      # "high" | "medium" | "low"
    start: int         # inclusive index into the scanned text
    end: int           # exclusive index
    label: str         # human-readable, e.g. "GitHub token"

    def span(self) -> tuple[int, int]: ...   # returns (start, end)
```

### 2.2 公开接口（签名必须完全一致）

```python
def scan(text: str) -> tuple[SensitiveHit, ...]:
    """Return all hits, sorted by (start, end, kind). Overlapping hits are
    de-duplicated: the earlier and longer match wins. Never raises."""

def has_sensitive(text: str) -> bool:
    """True if scan() returns at least one hit."""

def redact(text: str) -> str:
    """Replace every hit span with '<redacted:KIND>'. Must be safe when
    spans overlap (apply from the end backwards) and must never raise."""

def summarize(hits: tuple[SensitiveHit, ...]) -> str:
    """One-line English summary, e.g.
    '2 high, 1 low: github_token x1, email x2'. Empty tuple -> 'no sensitive data'."""
```

### 2.3 检测规则（照抄；正则必须逐条实现）

`_RULES` 是模块级元组，每项含 `kind` / `severity` / `pattern` / `label`：

| kind | severity | 正则（Python `re`） | label |
|---|---|---|---|
| `private_key` | high | `-----BEGIN [A-Z ]*PRIVATE KEY-----` | Private key block |
| `aws_access_key` | high | `\b(?:AKIA\|ASIA)[0-9A-Z]{16}\b` | AWS access key id |
| `github_token` | high | `\b(?:ghp\|gho\|ghu\|ghs\|ghr)_[A-Za-z0-9]{36}\b\|\bgithub_pat_[A-Za-z0-9_]{22,}\b` | GitHub token |
| `api_key_prefix` | high | `\bsk-[A-Za-z0-9_-]{20,}\b` | OpenAI-style API key |
| `slack_token` | high | `\bxox[abprs]-[A-Za-z0-9-]{10,}\b` | Slack token |
| `google_api_key` | medium | `\bAIza[0-9A-Za-z_-]{35}\b` | Google API key |
| `jwt` | medium | `\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b` | JSON Web Token |
| `bearer_token` | medium | `(?i)\bbearer\s+[A-Za-z0-9._~+/-]{20,}=*` | Bearer token |
| `url_credentials` | high | `(?i)\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s:/@]+@` | Credentials in URL |
| `secret_assignment` | medium | `(?i)\b[A-Z][A-Z0-9_]*(?:TOKEN\|SECRET\|PASSWORD\|PASSWD\|API_?KEY\|ACCESS_?KEY\|PRIVATE_?KEY)\s*[=:]\s*\S{8,}` | Secret-looking assignment |
| `ssh_private_key` | high | `(?i)(?:[/\\]\.ssh[/\\]id_(?:rsa\|dsa\|ecdsa\|ed25519)\b\|[/\\]\.ssh[/\\])` | SSH private key path |
| `cloud_credential` | high | `(?i)(?:[/\\]\.aws[/\\]credentials\b\|[/\\]\.config[/\\]gcloud[/\\]\|[/\\]\.azure[/\\]\|[/\\]\.kube[/\\]config\b)` | Cloud credential file |
| `dotenv_file` | medium | `(?i)(?:^\|[\s/\\'\"])\.env(?:\.(?:local\|production\|prod\|dev\|development\|test))?\b` | .env file |
| `email` | low | `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b` | Email address |
| `cn_mobile` | low | `(?<!\d)1[3-9]\d{9}(?!\d)` | CN mobile number |
| `cn_id_card` | low | `(?<!\d)\d{17}[\dXx](?!\d)` | CN ID card number |
| `card_number` | medium | `(?<!\d)(?:\d{4}[ -]?){3}\d{4}(?!\d)` | Card-like number |

### 2.4 降噪规则（必须实现，否则误报会淹没用户）

1. **`card_number` 必须过 Luhn 校验**：把匹配串去掉空格/连字符后取数字，长度必须是 16，
   且 `_luhn_ok(digits)` 为真才产出 hit。Luhn 校验函数自己写（标准算法，约 8 行）。
2. **`email` 占位域名白名单**：域名（`@` 之后）大小写不敏感地等于下列之一时不产出 hit：
   `example.com` / `example.org` / `example.net` / `test.com` / `localhost` /
   `noreply.github.com` / `users.noreply.github.com` / `*.example.com`（子域也算）。
3. **`secret_assignment` 占位值白名单**：赋值右侧若是下列之一（大小写不敏感、去引号后）不产出 hit：
   `your_key_here` / `your_token_here` / `changeme` / `placeholder` / `xxx` / `todo` /
   `<your-key>` / `$ENV_VAR` / `${ENV_VAR}` / `%ENV_VAR%`（`$` 或 `%` 开头的变量引用一律跳过）。

### 2.5 行为要求

- `scan("")` → `()`；`scan(None)` 之类非字符串输入 → 返回 `()`，**不得抛异常**
- 重叠命中：只保留**起始位置更早、长度更长**的那个（例：`sk-` 长串里若同时命中 `jwt`，取更长者）
- 所有正则必须在**模块加载时**编译一次（`re.compile`），不得在 `scan()` 里重复编译
- `redact()` 必须从右往左替换，避免位移错误
- 禁止使用 `re.MULTILINE`/`re.DOTALL`（规则表里已含需要的锚点）

### 2.6 自测要求

文件末尾加 `if __name__ == "__main__":`，用**纯 `assert`**（不要 pytest），覆盖：

**必须命中（至少 12 条）**，每条断言 `kind` 与 `severity` 正确。

> ⚠️ 夹具必须**在运行时拼装**，源码里不得出现完整 token。GitHub 的推送保护只按形状匹配，一个逼真的测试夹具会被当成真凭据而拒绝推送（本项目踩过：`xoxb-…` 被判为 Slack API Token）。写法：`_fake("xoxb-", "123456789012-", "abcdefghijklmnop")`。

| 形状 | 期望 `kind` | 期望 `severity` |
|------|------------|----------------|
| `-----BEGIN RSA PRIVATE KEY-----` | `private_key` | HIGH |
| `AKIA` + 16 位大写字母数字 | `aws_access_key` | HIGH |
| `ghp_` + 36 位字母数字 | `github_token` | HIGH |
| `sk-` + 20 位以上小写字母 | `api_key_prefix` | HIGH |
| `xoxb-` + 数字 `-` 字母 | `slack_token` | HIGH |
| `AIza` + 35 位字母数字 | `google_api_key` | MEDIUM |
| `eyJ….eyJ….` 三段 base64url | `jwt` | MEDIUM |
| `Authorization: Bearer <32+>` | `bearer_token` | MEDIUM |
| `https://user:pass@host/…` | `url_credentials` | HIGH |
| `*_API_KEY=<16+>` | `secret_assignment` | MEDIUM |
| `rm -rf …/.ssh/id_rsa` | `ssh_private_key` | HIGH |
| `cat ~/.aws/credentials` | `cloud_credential` | HIGH |
| `> .env.local` | `dotenv_file` | MEDIUM |
| `alice@realcorp.com` | `email` | LOW |
| `13812345678` | `cn_mobile` | LOW |
| `4111 1111 1111 1111`（过 Luhn） | `card_number` | MEDIUM |

**必须不命中（至少 8 条）**：
```
alice@example.com
your_key_here
API_KEY=your_token_here
export API_KEY=$MY_KEY
export API_KEY=${MY_KEY}
echo $HOME
ls -la
1234 5678 9012 3456          # 16 位但不满足 Luhn
1381234567890                # 13 位，非手机号
20260909                     # 8 位日期
.gitignore
```

## 3. 交付方式

1. 用工具**直接创建** `qoder_guard/sensitive.py`（路径相对工程根 `qoder-sentinel/`）
2. 完成后**回报**：
   - 文件绝对路径
   - 行数
   - 内置断言条数（命中 / 不命中各多少）
   - **任何你认为规格有歧义的地方——先报告，不要自行猜测后硬写**

## 4. 明确不要做的事

- ❌ 不要改 `qoder_guard/hooks.py` 或任何已有文件（集成由主调度方负责）
- ❌ 不要装依赖、不要跑测试、不要 git commit
- ❌ 不要写 `THIRD_PARTY_LICENSES.md` / README（主调度方负责）
- ❌ 不要在代码里写中文（含注释与测试数据注释）
- ❌ 不要为「顺便优化」而新增未在 2.2 列出的公开函数
