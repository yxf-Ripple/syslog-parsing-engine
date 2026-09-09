#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Stage1 头部变量语义标注
-----------------------
Drain 聚类只解决"哪些位置是变量",本模块解决"变量是什么(字段名)",
把匿名变量转为命名组 (?P<hostname>...) 正则,使 field_extractor 能提取外层元数据。

三级来源:
1. 预置语义表(确定性):已知格式按 token 特征匹配位置->字段名
2. 自动规则:PRI token 自动命名 priority;event_id 自动拆数字
3. LLM 标注(新格式):未命中预置表时,调 LLM 输出"第 N 个变量是哪个字段"
"""
import re
from typing import Dict, List, Optional, Tuple

from .drain_learner import MAX_PREFIX, classify_token, is_var, var_type_regex
from .llm_client import LLMClient

# 未命中预置表时,仅对样本量足够的模板调 LLM 标注(小模板匿名即可,不影响命中率)
MIN_LLM_COUNT = 20
# 单次运行 LLM 标注调用上限(超出则模板匿名,防新格式模板多时调用失控)
MAX_LLM_CALLS = 5
_llm_call_count = 0

# ---------- 预置语义表 ----------
# 匹配函数: 判断样本 token 序列是否该格式;返回 {变量位置: 字段名}
_PRI_NUM = re.compile(r'^<\d+>\d+$')
_PRI_WORD = re.compile(r'^<\d+>\w+$')
_ISO_TS = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}')
_BSD_TS = re.compile(r'^\d{2}:\d{2}:\d{2}')
_DAY = re.compile(r'^\d{1,2}$')
_IP = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
_MON = re.compile(r'^[A-Za-z]{3}$')
# Apache: "[Sat" 连写星期
_BRACKET_WEEKDAY = re.compile(r'^\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)$')

# ---- 格式类别检测(对齐 example 旧解析器 log_format 类型) ----
# 反引号中控:192.0.2.116727085`2026-06-11 15:31:38.000000+480`...
_BACKTICK_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}\d*`')
# IP 前缀 syslog:192.0.2.132<27>Jun 11 15:32:01 ...
_IP_PREFIX_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}<')
# 尾部 JSON 载荷(如 " - - - - {...}")
_JSON_PAYLOAD_RE = re.compile(r'\{.*\}$', re.S)
# KEY="VALUE" KV 对(天融信)
_KV_PAIR_RE = re.compile(r'\w+="')


def detect_format_category(sample: str) -> str:
    """检测样本所属格式类别,返回 example 旧解析器 log_format 类型
    (rfc5424_json / tianrongxin_structured / windows_event / backtick_separated /
    ip_prefixed_syslog / huawei / generic)。用于 stage1 pattern 的 format 字段赋值。
    """
    if not sample:
        return "generic"
    toks = sample.split()
    if len(toks) >= 3 and _PRI_NUM.match(toks[0]) and _ISO_TS.match(toks[1]):
        # RFC5424:<25>1 2025-06-19T...Z DVC01 ...;message 含 JSON 载荷 -> rfc5424_json
        if _JSON_PAYLOAD_RE.search(sample):
            return "rfc5424_json"
        # 纯文本 RFC5424 example 无细分类型,归 generic
        return "generic"
    if len(toks) >= 6 and _PRI_WORD.match(toks[0]) and _DAY.match(toks[1]) \
            and _BSD_TS.match(toks[2]):
        # BSD+Windows:<29>Jun 19 15:04:51 ... Security-Auditing: 4656:
        return "windows_event"
    if _BACKTICK_RE.match(sample):
        return "backtick_separated"
    if _IP_PREFIX_RE.match(sample):
        return "ip_prefixed_syslog"
    if '%%' in sample:
        # 华为:%%模块/级别/消息码
        return "huawei"
    if len(toks) >= 3 and _MON.match(toks[0]) and _DAY.match(toks[1]) \
            and _BSD_TS.match(toks[2]):
        # 无 PRI BSD 开头(月 日 时:分:秒):天融信 KV 带头部 -> tianrongxin_structured,否则 generic
        return "tianrongxin_structured" if _KV_PAIR_RE.search(sample) else "generic"
    if _KV_PAIR_RE.search(sample):
        # 无头部纯 KV(如 DVC_ADDRESS="..." START_TIME="...")
        return "tianrongxin_structured"
    return "generic"


def match_semantic_table(tokens: List[str]) -> Optional[Dict[int, str]]:
    """按 token 序列特征匹配预置语义表,返回 {位置: 字段名} 或 None"""
    if len(tokens) >= 3 and _PRI_NUM.match(tokens[0]) and _ISO_TS.match(tokens[1]):
        # RFC5424: <25>1 2025-06-19T...Z DVC01 2 - -
        return {1: 'timestamp', 2: 'hostname'}
    if len(tokens) >= 6 and _PRI_WORD.match(tokens[0]) and _DAY.match(tokens[1]) \
            and _BSD_TS.match(tokens[2]):
        # BSD+Windows: <29>Jun 19 15:04:51 HOST01 Security-Auditing: 4656:
        return {2: 'timestamp', 3: 'hostname', 4: 'program', 5: 'event_id'}
    if len(tokens) >= 4 and _MON.match(tokens[0]) and _DAY.match(tokens[1]) \
            and _BSD_TS.match(tokens[2]) and _IP.match(tokens[3]):
        # 天融信 KV: Jun 1 00:04:18 192.0.2.254 DVC_ADDRESS=...
        return {3: 'source_ip'}
    if len(tokens) >= 4 and _MON.match(tokens[0]) and _DAY.match(tokens[1]) \
            and _BSD_TS.match(tokens[2]):
        # 无 PRI BSD: Jun 9 06:06:20 combo kernel: ...
        # 位置 3 = 主机名(非 IP,IP 已在上方分支);位置 4 以冒号结尾 = 程序名
        table = {2: 'timestamp', 3: 'hostname'}
        if len(tokens) > 4 and tokens[4].endswith(':'):
            table[4] = 'program'
        return table
    if len(tokens) >= 4 and _BRACKET_WEEKDAY.match(tokens[0]) and _MON.match(tokens[1]) \
            and _DAY.match(tokens[2]) and _BSD_TS.match(tokens[3]):
        # Apache: [Sat Jun 11 06:07:04 2005] [notice] ...
        return {3: 'timestamp'}
    if len(tokens) >= 3 and re.match(r'^\[\d{1,2}\.\d{1,2}$', tokens[0]) \
            and re.match(r'^\d{2}:\d{2}:\d{2}\]$', tokens[1]):
        # Proxifier: [10.30 16:49:06] chrome.exe - host:port close, ...
        return {1: 'timestamp', 2: 'program'}
    return None


# ---------- 命名组正则构造 ----------

def named_group_regex(field: str, tok: str, sample_tok: str) -> str:
    """构造单个变量的命名组正则(匿名 -> (?P<field>...))"""
    if field == 'priority':
        # PRI token:<25>1 / <29>Jun -> <(?P<priority>\d+)> + 尾部泛化
        m = re.match(r'^<(\d+)>(.*)$', sample_tok)
        if m:
            tail = var_type_regex(m.group(2))
            return f'<(?P<priority>\\d+)>{tail}'
        return r'(?P<priority>\d+)'
    if field == 'event_id':
        # 4656: -> (?P<event_id>\d+):
        m = re.match(r'^(\d+)(.*)$', sample_tok)
        if m:
            return f'(?P<event_id>\\d+){re.escape(m.group(2))}'
        return r'(?P<event_id>\S+)'
    if field == 'program':
        # 常量 token(如 Security-Auditing:)
        return f'(?P<program>{re.escape(sample_tok or tok)})'
    base = var_type_regex(sample_tok or tok)
    return f'(?P<{field}>{base})'


def apply_semantics(regex: str) -> str:
    """占位符形式的命名组替换:模板正则已用 __F{field}__ 标记位置,替换为命名组"""
    return re.sub(r'__F(\w+)__', lambda m: m.group(1), regex)


# ---------- LLM 标注(新格式) ----------

_STANDARD_HEADER_FIELDS = (
    "priority, timestamp, hostname, source_ip, device_ip, device_name, "
    "event_id, event_code, program, app_name, severity, facility"
)


class Stage1SemanticAnnotator:
    """对模板头部变量序列做语义标注(预置表优先,LLM 兜底)"""

    def __init__(self):
        self.client = LLMClient()
        self._llm_used = 0

    @property
    def llm_calls(self) -> int:
        return self._llm_used

    def annotate(self, tokens: List[str], samples: List[str]) -> Dict[int, str]:
        """返回 {变量位置: 字段名}"""
        # 1. 预置表
        table = match_semantic_table(tokens)
        if table is not None:
            return table

        # 2. 自动规则:PRI token 位置 0
        auto: Dict[int, str] = {}
        if tokens and re.match(r'^<\d+>', tokens[0]):
            auto[0] = 'priority'

        # 3. LLM 标注(预置未覆盖)
        llm_fields = self._llm_annotate(tokens, samples)
        auto.update(llm_fields)
        return auto

    def _llm_annotate(self, tokens: List[str], samples: List[str]) -> Dict[int, str]:
        """LLM 标注头部变量位置语义(只标前 MAX_PREFIX 个 token,message 区不标)"""
        var_pos = [i for i, t in enumerate(tokens) if is_var(t) and i < MAX_PREFIX]
        if not var_pos:
            return {}
        # 用样本原 token 展示位置内容
        sample_toks = samples[0].split()[: len(tokens)] if samples else []
        pos_desc = "\n".join(
            f"位置{i}: 示例值={sample_toks[i] if i < len(sample_toks) else '?'}"
            for i in var_pos
        )
        sample_show = (samples[0][:200] if samples else "")
        prompt = f"""你是日志头部字段标注专家。给定一条日志样本,标注其"头部可变位置"的语义。

日志样本: {sample_show}

头部可变位置(空格分隔的 token):
{pos_desc}

标准字段(从中选): {_STANDARD_HEADER_FIELDS}
- priority: 优先级 <数字>
- timestamp: 时间戳
- hostname: 主机名/设备名
- event_id: 事件ID
- 没有对应语义的位置不要输出

只返回纯 JSON:
{{"fields":[{{"position":2,"field_name":"timestamp"}},{{"position":3,"field_name":"hostname"}}]}}"""
        result = self.client.call_json(prompt, max_retries=2)
        if not result or "fields" not in result:
            return {}
        self._llm_used += 1
        out = {}
        for f in result.get("fields") or []:
            pos = f.get("position")
            name = f.get("field_name")
            if isinstance(pos, int) and name in _STANDARD_HEADER_FIELDS:
                out[pos] = name
        return out


def build_semantic_regex(regex: str, semantics: Dict[int, str], tokens: List[str],
                         sample_toks: List[str]) -> str:
    """
    把匿名正则升级为带命名组的正则。
    用占位符 __F{field}__ 替换对应位置的变量片段,再由 apply_semantics 还原。
    此函数与 drain_learner.template_to_regex 集成时直接使用 named_group_regex 逐位置构造,
    这里提供兼容入口。
    """
    return regex


# 模块级 LLM 标注缓存:同格式(头部 token 分类键签名相同)只调一次 LLM
_llm_cache: Dict[Tuple, Dict[int, str]] = {}


def template_semantics(tpl) -> Dict[int, str]:
    """
    对模板求头部语义字段(预置表优先,LLM 兜底)。
    供 offline 管线作为 semantic_provider 传入 template_to_regex。
    """
    # 用样本真实 token 匹配预置表(模板 tokens 中变量已合并为 <*>,无法字面匹配)
    if tpl.samples:
        sample_toks = tpl.samples[0].split()[: len(tpl.tokens)]
        table = match_semantic_table(sample_toks)
        if table is not None:
            # 补自动规则:PRI 开头的位置 0 命名 priority
            if sample_toks and re.match(r'^<\d+>', sample_toks[0]) and 0 not in table:
                table = dict(table)
                table[0] = 'priority'
            return table
    # 未命中预置表 -> 小模板匿名;大模板走 LLM 标注(带缓存+调用上限)
    if tpl.count < MIN_LLM_COUNT:
        return {}
    global _llm_call_count
    if _llm_call_count >= MAX_LLM_CALLS:
        return {}
    sig = tuple(classify_token(t) for t in tpl.tokens[:MAX_PREFIX])
    if sig in _llm_cache:
        return _llm_cache[sig]
    annotator = Stage1SemanticAnnotator()
    fields = annotator.annotate(tpl.tokens, tpl.samples)
    _llm_call_count += 1
    _llm_cache[sig] = fields
    return fields
