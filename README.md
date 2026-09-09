# Syslog 解析引擎

将各类 syslog 日志自动解析为统一结构的 JSON(JSONL 格式),支持工控平台、Windows 审计、天融信 KV、安管平台、Linux/BSD 等格式。

**核心思路**:离线自动学模板 + 在线快速纯正则转化,在线全程零 LLM。

---

## 整体架构

```
┌─ 离线学习(有充足时间)───────────────────────────────┐
│  日志文件 → ① Stage1: 标准前缀树 Drain 聚类         │
│             → 正则(含命名组)→ stage1_patterns.yaml │
│           → ② Stage2: LLM 字段标注(可选)           │
│             → 字段提取规则 → stage2_patterns.yaml  │
└───────────────────────────────────────────────────┘
┌─ 在线转化(必须快)─────────────────────────────────────┐
│  日志流 → Stage1 正则匹配 → 阶段1提取(命名组/PRI/KV)    │
│        → Stage2 规则提取(字段) → schema 对齐 → JSONL   │
│        (纯正则,零 LLM,数千行/秒)                       │
└──────────────────────────────────────────────────────┘
```

- **Stage1(结构层)**:标准前缀树 Drain 聚类,把"头部结构相同"的日志合并为一个正则(含 `priority/timestamp/hostname/event_id` 等命名组);
- **Stage2(语义层)**:LLM 标注"引导形式 → 标准字段"映射(如 `源地址 → source_ip`、`dev_ip → device_ip`),由代码确定性生成提取正则——**不写死任何针对具体格式的键名表**;
- **在线**:纯正则匹配 + 字段提取,不调用 LLM。

---

## 目录结构

```
src/
  main.py              在线转化 CLI(入口)
  offline_drain.py     单文件 Drain 学习 + stage1 YAML 写入
  parser/
    drain_learner.py   标准前缀树 Drain 学习器
    stage1_semantics.py Stage1 头部语义标注(预置标准格式 + LLM 兜底)
    llm_annotator.py   Stage2 字段标注(LLM)+ 引导形式检测/分组
    field_rules.py     LLM 映射 → 提取规则生成器(无预置表)
    field_extractor.py 阶段1/阶段2 提取(命名组、PRI、KV、JSON、message_content)
    stage2_extractor.py Stage2 规则提取(JSON/KV/regex)
    schema.py          输出字段对齐(example 25 字段)
    pattern_loader.py  stage1 YAML 加载/匹配
scripts/
  learn_files.py       批量离线学习(推荐入口,stage1 + stage2 一步完成)
  rebuild_stage2.py    重建 stage2 规则
  preview.py           JSONL 查看
  verify_stage2.py     Stage2 字段提取验证
  test_perturb_robustness.py  扰动回归测试
  export_result.py     导出主文件到 result/
testdata/              测试日志(各格式)
stage1_patterns.yaml   学出的正则库(产物)
stage2_patterns.yaml   字段提取规则(产物)
result/                转化输出 JSONL(产物)
```

---

## 安装

```bash
pip install -r requirements.txt
# 依赖: openai / pyyaml / python-dotenv
```

LLM 标注需要 `.env` 配置(离线学习时才用到,在线转化不需要)。复制 `.env.example` 为 `.env`:

```bash
LLM_ENABLED=true
LLM_BASE_URL=http://<llm-gateway-host>:9901/v1   # 本地 qwen3 网关
LLM_API_KEY=                                # 本地网关免鉴权,留空即可
LLM_MODEL=qwen3
LLM_MAX_TOKENS=4096
```

---

## 使用

### 1. 离线学习(学新格式)

```bash
# 学习目录下所有 *.log,自动完成 Stage1(正则)+ Stage2(LLM 标注字段)
python scripts/learn_files.py --dir testdata \
  --output stage1_patterns.yaml --stage2 stage2_patterns.yaml

# 或指定具体文件(增量学习推荐:只列新增文件,避免重复扫描)
python scripts/learn_files.py "testdata/额外/工控平台1#GW032#2024-07-05.log" \
  --output stage1_patterns.yaml --stage2 stage2_patterns.yaml

# 跳过 LLM 标注(只学 stage1 正则)
python scripts/learn_files.py --dir testdata --no-llm \
  --output stage1_patterns.yaml --stage2 stage2_patterns.yaml
```

### 2. 在线转化(纯正则,零 LLM)

```bash
python -m src.main -i "testdata/额外/工控平台1#GW032#2024-07-05.log" -o result/gk.jsonl
python -m src.main -i testdata/额外/udp_syslog.log -o result/udp.jsonl

# 可选参数
#   -e 文件      未匹配的行写入错误文件
#   -p 文件      指定 stage1 YAML(默认 stage1_patterns.yaml)
#   --nested     启用嵌套 syslog 剥壳
```

### 3. 查看结果

```bash
python scripts/preview.py result/gk.jsonl -n 3            # 前 3 条
python scripts/preview.py result/gk.jsonl --fields device_name,message_content
python scripts/preview.py result/gk.jsonl --grep 192.0.2.1   # 过滤
python scripts/preview.py result/gk.jsonl --summary       # 字段统计
```

### 4. 验证

```bash
python scripts/verify_stage2.py        # Stage2 字段提取验证
python scripts/test_perturb_robustness.py  # 扰动回归(日期+1/PRI/主机名扰动)
```

---

## 输出字段

每行 JSON 为一条解析结果,**顶层按 example 25 字段输出**(无值用空字符串,与 example 风格一致):

| 字段 | 含义 |
|---|---|
| `priority` / `facility` / `severity` | syslog PRI(设施/严重度) |
| `timestamp` | 日志时间(CST) |
| `syslog_ip` | 采集源 IP |
| `hostname` | 主机名/设备名 |
| `event_id` | 原始事件 ID(如 4656、7001) |
| `device_ip` / `device_name` / `device_type` | 设备 IP / 名称 / 类型 |
| `source_device_ip/name/type` | 源设备(与 device_* 同值,example 保留) |
| `structured_data` | 结构化数据(如嵌套 syslog) |
| `original_data` | 原始词条(仅当 KV 中存在 `ORIGINAL_DATA="..."`) |
| `message_content` | **告警信息**(syslog 出现的原因,全格式提取,见下) |
| `raw_message` | `message_content[:500]` 截断版 |
| `source_ip` / `destination_user` / `source_user` | 源 IP / 目的用户 / 源用户 |
| `data_object_type` / `file_name` / `dvc_event_category` / `agent_address` | 设备对象类型/文件名/事件类别/代理地址 |

附加字段(有意义、不与上面重复):

| 字段 | 含义 |
|---|---|
| `event_type` | 事件分类枚举(SECURITY_ALERT / AUTHENTICATION / SYSTEM_ERROR / SYSTEM_EVENT / ...) |
| `risk_level` | 风险等级(INFO / LOW / MEDIUM / HIGH / CRITICAL) |
| `received_at` / `parse_success` / `parse_errors` | 接收时间 / 解析是否成功 / 错误列表 |
| `message_content_decision` | **message_content 来源说明**(见下) |
| `parsed_content` | 只保存原始 syslog 整行内容 |
| `username` / `user_domain` / `protocol` / `source_port` / `destination_port` | 用户/协议/端口(有值才输出) |

### message_content(告警信息)与决定栏

`message_content` 是**告警信息**——日志存在的意义,全格式必提取。来源由代码按内容特征**自动决定**(不针对格式硬编码),并输出 `message_content_decision` 说明依据:

- `JSON 载荷 event_content 字段` — 工控平台等 JSON 载荷格式;
- `KV 的 MESSAGE 字段` — 天融信等 `KEY="VALUE"` 格式;
- `message 组内容(告警描述)` — BSD / Windows / 安管等 message 组;
- `无法自动决定,已回退整条 message,请人工确认` — 兜底:取不到告警信息时,message_content = 整条 message,由人工确认。

中文/转义:原始数据中的 `\uXXXX`(单/双重转义)统一解码为真实中文(给人看);`\r\n`/`\t` 还原为换行/制表符(Windows 事件原始排版)。

---

## 已知限制与注意事项

1. **在线零 LLM**:新格式必须先离线学习(Stage1 正则),未学习格式的行会未匹配(可写 `-e` 错误文件排查);
2. **LLM 标注成本**:Stage2 每格式约 1~8 次 LLM 调用(按 message 结构分组),每次 40~80s;可用 `--no-llm` 跳过(产出空规则);
3. **低 count 模板过滤**:`count < 3` 的模板组不导出(噪声行如"注销成功"会被忽略,正常格式覆盖不受影响);
4. **同一文件多格式**:一个日志文件可包含多种格式(如工控文件含 JSON 载荷与 Windows 事件),各自正则匹配,互不干扰;
5. **上游转义深度不一致**:同一批数据里 `\uXXXX` 可能是单转义也可能是双重转义(多层转发导致),已统一递归解码;
6. **Windows 事件消息**:message_content 中的 `%%数字`(参数占位符)、`S-1-5-18`(SID)、`%{SID}`(组成员)是 Windows 事件日志的标准原文,非乱码。
