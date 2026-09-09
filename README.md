# Syslog 解析引擎

将多种格式的 syslog 日志自动解析为统一结构的 JSON（JSONL 格式），覆盖工控平台、Windows 审计、天融信 KV、安管平台、Linux/BSD 等常见格式。

**核心设计**：离线自动学习解析模板，在线采用纯正则快速转化，在线阶段全程不依赖 LLM。

---

## 整体架构

```
┌─ 离线学习（时间充裕，可启用 LLM）─────────────────────┐
│  日志文件 → ① Stage1：前缀树 Drain 聚类               │
│             → 正则（含命名组）→ stage1_patterns.yaml  │
│           → ② Stage2：LLM 字段标注（可选）            │
│             → 字段提取规则 → stage2_patterns.yaml     │
└─────────────────────────────────────────────────────┘
┌─ 在线转化（要求高吞吐，零 LLM）────────────────────────┐
│  日志流 → Stage1 正则匹配 → 头部字段提取（命名组/PRI/KV）│
│        → Stage2 规则提取 → 字段对齐 → JSONL            │
│        （纯正则，数千行/秒）                            │
└─────────────────────────────────────────────────────┘
```

- **Stage1（结构层）**：基于标准前缀树 Drain 聚类，将头部结构一致的日志归并为一条正则（含 `priority / timestamp / hostname / event_id` 等命名组）；
- **Stage2（语义层）**：由 LLM 标注"引导形式 → 标准字段"映射（如 `源地址 → source_ip`、`dev_ip → device_ip`），代码据此确定性生成提取正则——**不内置任何针对特定厂商格式的键名映射表**；
- **在线**：仅执行正则匹配与字段提取，不调用 LLM。

---

## 目录结构

```
src/
  main.py               在线转化 CLI（入口）
  offline_drain.py      Stage1 离线 Drain 学习 + YAML 写入
  parser/
    drain_learner.py    前缀树 Drain 学习器
    stage1_semantics.py Stage1 头部语义标注（预置标准格式识别 + LLM 兜底）
    llm_annotator.py    Stage2 字段标注（LLM）+ 引导形式检测/分组
    field_rules.py      LLM 映射 → 提取规则生成器（无预置表）
    field_extractor.py  阶段 1/阶段 2 字段提取（命名组、PRI、KV、JSON、message_content）
    stage2_extractor.py Stage2 规则提取（JSON / KV / regex）
    schema.py           输出字段对齐（25 个标准字段）
    pattern_loader.py   stage1 YAML 加载与匹配
scripts/
  learn_files.py        批量离线学习（推荐入口：stage1 + stage2 一步完成）
  rebuild_stage2.py     重建 stage2 规则
  test_llm_connection.py  LLM 网关连通性自检
stage1_patterns.yaml    Stage1 正则库（运行产物，仓库内为空的占位文件）
stage2_patterns.yaml    Stage2 字段规则库（运行产物，仓库内为空的占位文件）
result/                 转化输出 JSONL（运行产物，已忽略提交）
.env.example            LLM 配置模板（复制为 .env 后填写）
```

> `testdata/`、`result/` 等为本地运行目录；仓库仅包含引擎代码与文档。`stage1_patterns.yaml`、`stage2_patterns.yaml` 在仓库中为占位空文件，需通过离线学习生成实际规则（见下）。

---

## 安装与配置

```bash
pip install -r requirements.txt
# 依赖：openai / pyyaml / python-dotenv
```

LLM 标注仅在**离线学习**阶段使用，在线转化无需配置。复制 `.env.example` 为 `.env` 并填写：

```bash
LLM_ENABLED=true
LLM_BASE_URL=http://<llm-gateway-host>:9901/v1   # 本地 LLM 网关地址
LLM_API_KEY=                                     # 网关免鉴权时留空
LLM_MODEL=qwen3
LLM_MAX_TOKENS=4096
```

---

## 使用指南

### 1. 离线学习（生成 Stage1 / Stage2 规则）

```bash
# 学习目录下全部 *.log，自动完成 Stage1（正则）与 Stage2（LLM 字段标注）
python scripts/learn_files.py --dir testdata \
  --output stage1_patterns.yaml --stage2 stage2_patterns.yaml

# 增量学习指定文件（推荐只传入新增文件，避免重复扫描）
python scripts/learn_files.py "testdata/额外/工控平台1#DVC01#2024-07-05.log" \
  --output stage1_patterns.yaml --stage2 stage2_patterns.yaml

# 跳过 LLM 标注（仅学习 Stage1 正则）
python scripts/learn_files.py --dir testdata --no-llm \
  --output stage1_patterns.yaml --stage2 stage2_patterns.yaml
```

### 2. 在线转化（纯正则，零 LLM）

```bash
python -m src.main -i "testdata/额外/工控平台1#DVC01#2024-07-05.log" -o result/gk.jsonl
python -m src.main -i testdata/额外/udp_syslog.log -o result/udp.jsonl

# 可选参数
#   -e 文件      未匹配的行写入错误文件
#   -p 文件      指定 stage1 YAML（默认 stage1_patterns.yaml）
#   --nested     启用嵌套 syslog 剥壳
```

### 3. 离线学习与在线转化并行运行

两者的设计允许在部署中同时运行，互不阻塞：

- **规则库写入为原子操作**：`learn_files.py` / `rebuild_stage2.py` 写 `stage1_patterns.yaml`、`stage2_patterns.yaml` 时均采用"先写临时文件、再原子替换"（`os.replace`），在线进程在任意时刻读取到的都是完整快照，不会读到半写入的中间状态。
- **在线实例一次加载、运行期不重读**：`main.py` 启动时通过 `PatternLoader` 一次性加载全部正则；Stage2 提取器为进程内单例，仅在进程启动时加载规则文件。
- **推荐部署方式**：在线实例持续运行解析日志期间，可在后台随时执行 `learn_files.py` 学习新增日志格式；正在运行实例的既有规则不受影响，旧格式解析不中断。
- **生效边界（重要）**：已运行的在线进程**不会自动感知**新学习到的规则——新格式需在在线进程重启（重新加载规则文件）后才会被命中。代码当前未实现热更新/自动重载机制；`settings.py` 中的 `LLM_TRIGGER_*` 仅为预留配置项，src 内尚无对应实现。若需不停机生效，应自行增加规则文件的热重载逻辑。

---

## 输出字段

每行 JSON 为一条解析结果，顶层固定输出 25 个标准字段（无值以空字符串占位），并附若干有意义的附加字段：

| 字段 | 含义 |
|---|---|
| `priority` / `facility` / `severity` | syslog PRI（设施 / 严重度） |
| `timestamp` | 日志时间（CST） |
| `syslog_ip` | 采集源 IP |
| `hostname` | 主机名 / 设备名 |
| `event_id` | 原始事件 ID（如 4656、7001） |
| `device_ip` / `device_name` / `device_type` | 设备 IP / 名称 / 类型 |
| `source_device_ip/name/type` | 源设备（与 `device_*` 同值，字段兼容保留） |
| `structured_data` | 结构化数据（如嵌套 syslog） |
| `original_data` | 原始词条（仅当 KV 中存在 `ORIGINAL_DATA="..."`） |
| `message_content` | **告警信息**（日志触发原因，各格式均提取，见下） |
| `raw_message` | `message_content[:500]` 截断版本 |
| `source_ip` / `destination_user` / `source_user` | 源 IP / 目的用户 / 源用户 |
| `data_object_type` / `file_name` / `dvc_event_category` / `agent_address` | 对象类型 / 文件名 / 事件类别 / 代理地址 |

附加字段（仅在取值有意义且不与上述字段重复时输出）：

| 字段 | 含义 |
|---|---|
| `event_type` | 事件分类枚举（SECURITY_ALERT / AUTHENTICATION / SYSTEM_ERROR / SYSTEM_EVENT / ...） |
| `risk_level` | 风险等级（INFO / LOW / MEDIUM / HIGH / CRITICAL） |
| `received_at` / `parse_success` / `parse_errors` | 接收时间 / 是否解析成功 / 错误列表 |
| `message_content_decision` | `message_content` 来源判定说明（见下） |
| `parsed_content` | 原始 syslog 整行内容 |
| `username` / `user_domain` / `protocol` / `source_port` / `destination_port` | 用户 / 域 / 协议 / 端口（有值才输出） |

### message_content 的提取策略

`message_content` 为告警信息，是每条日志的核心语义，各格式均需提取。提取来源由代码按内容特征自动判定（不对具体格式硬编码），并通过 `message_content_decision` 字段记录判定依据：

- `JSON 载荷 event_content 字段` —— 工控平台等携带 JSON 载荷的格式；
- `KV 的 MESSAGE 字段` —— 天融信等 `KEY="VALUE"` 格式；
- `message 组内容（告警描述）` —— BSD / Windows / 安管等格式；
- `无法自动决定，已回退整条 message，请人工确认` —— 兜底：无法定位告警信息时，取整条 message 交由人工确认。

字符处理：原始数据中的 `\uXXXX`（单层或双层转义）统一递归解码为可读文本；`\r\n` / `\t` 还原为换行与制表符（保留 Windows 事件原始排版）。

---

## 已知限制与注意事项

1. **在线零 LLM**：未学习过的新格式行无法匹配，可配合 `-e` 错误文件定位未命中样本；新格式需先执行离线学习。
2. **LLM 标注成本**：Stage2 每种格式约 1~8 次 LLM 调用（按 message 结构分组），单次约 40~80s；可用 `--no-llm` 跳过（产出空规则，仅保留预置识别）。
3. **低频模板过滤**：`count < 3` 的模板组不导出（抑制噪声，不影响正常格式的覆盖）。
4. **单文件多格式**：一个日志文件可能包含多种格式（如工控文件同时含 JSON 载荷与 Windows 事件），各格式分别匹配、互不干扰。
5. **上游转义深度不一致**：同一批数据中 `\uXXXX` 可能为单层或双层转义（多层转发所致），已统一递归解码。
6. **Windows 事件消息原文**：`message_content` 中的 `%%数字`（参数占位符）、`S-1-5-18`（SID）、`%{SID}`（组成员）为 Windows 事件日志标准原文，并非乱码。
