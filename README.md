# C2 Packet Analysis Skills

本仓库提供面向防御性分析的 Cursor Agent Skills，用于从已获取的样本、HTTP 报文或网络抓包中还原 Cobalt Strike 与 AntSword 的会话内容。

适用场景限于安全研究、应急响应与授权环境下的流量研判。请勿将其用于未授权访问或攻击活动。

## 仓库结构

```text
cobaltstrike-traffic-decrypt/          Cobalt Strike 流量解密技能
antsword-webshell-traffic-decrypt/     AntSword Webshell 流量解密技能
pyproject.toml                         Python 依赖声明
```

每个技能目录均包含：

- `SKILL.md`：技能入口与操作规则
- `references/workflow.md`：完整命令序列
- `scripts/`：当前推荐使用的分析脚本
- 相应第三方工具与示例样本

分析时请在对应技能目录下执行命令，不要从仓库根目录引用旧路径。

## 环境要求

- Python 3.10 或更高版本
- 可通过 `uv` 或 pip 安装 `pyproject.toml` 中的依赖

主要依赖包括 `pycryptodome`、`pyshark`、`javaobj-py3` 与 `pefile`。Cobalt Strike HTTP 流量解析还需要本机可用的 `tshark`。

## Cobalt Strike

技能目录：[`cobaltstrike-traffic-decrypt/`](cobaltstrike-traffic-decrypt/)

用于从 Beacon 样本中提取配置，恢复会话密钥，并解密 metadata 与 HTTP 流量。

| 组件 | 说明 |
|------|------|
| `cs-1768/1768.py` | 提取 Beacon 配置，推荐使用 JSON 输出 |
| `scripts/recover_cs_keys.py` | 汇总配置、转换公钥、由 `p`/`q` 重建私钥并解密 metadata |
| `cs-decrypt-metadata/cs-decrypt-metadata.py` | 使用已知或泄露的私钥解密 metadata |
| `cs-parse-http-traffic/cs-parse-http-traffic.py` | 使用 `rawkey` 解密 PCAP/PCAPNG 中的 HTTP 会话 |
| `cs-rsa/` | 附带 YAFU 与原始 RSA 辅助脚本；日常分析请优先使用 `recover_cs_keys.py` |

完整流程见 [`cobaltstrike-traffic-decrypt/SKILL.md`](cobaltstrike-traffic-decrypt/SKILL.md)。

`1768.py`、`cs-decrypt-metadata.py` 与 `cs-parse-http-traffic.py` 来自 [Didier Stevens](https://DidierStevens.com) 的公开工具。

## AntSword

技能目录：[`antsword-webshell-traffic-decrypt/`](antsword-webshell-traffic-decrypt/)

用于成对解析 AntSword Webshell 的请求与响应，还原操作者可见的命令与回显。

| 组件 | 说明 |
|------|------|
| `scripts/decrypt_antsword.py` | 请求/响应一键解码（推荐入口） |
| `scripts/decode_antsword_body.py` | 解析请求体中的 PHP loader、输出标记与命令 |
| `scripts/decode_http_gzip.py` | 从 Wireshark hex dump 或原始 HTTP 报文中解压 gzip/deflate |
| `scripts/extract_antsword_response.py` | 按请求侧标记提取真实响应载荷 |
| `antsword-traffic-decrypt/` | 原始脚本与示例报文，仅作对照与抽样验证 |

完整流程见 [`antsword-webshell-traffic-decrypt/SKILL.md`](antsword-webshell-traffic-decrypt/SKILL.md)。

## 使用说明

1. 根据目标协议进入对应技能目录。
2. 先阅读该目录下的 `SKILL.md`，再按 `references/workflow.md` 执行命令。
3. 优先使用 `scripts/` 中的封装脚本；子目录中的原始工具仅在对照或兼容旧流程时使用。
4. 仓库内样本（Beacon dump、PCAP、AntSword 报文）仅用于验证工具链，不代表完整实战覆盖。
