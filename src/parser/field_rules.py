#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLM 标注 → Stage2 提取规则生成器
--------------------------------
不包含任何针对具体厂商/格式的写死映射(预置表已按"普遍可行"要求移除)。
字段语义完全由 LLM 标注提供,本模块只负责把 LLM 的"引导形式映射"翻译为提取正则:

LLM 映射格式(三种引导形式):
- {"field_name", "kv_key"}              KEY="VALUE" 形式(如 SRC_ADDRESS) → kv_parse
- {"field_name", "token", "kind"}       中文标签:值 形式(如 源地址)       → regex
- {"field_name", "keyword", "kind"}     英文引导词:值 形式(如 from/port)  → regex
- {"field_name", "kind"}                裸值(独立 IP/数字,无引导词)        → regex(仅类型)

kind → 值正则: ip/port/protocol/username/path/number/time/text
"""
import re
from typing import Dict, List, Optional

from ..utils.logger import setup_logger

logger = setup_logger("field_rules")

# ---------- 类型 -> 正则 ----------

KIND_REGEX: Dict[str, str] = {
    'ip': r'(?:\d{1,3}\.){3}\d{1,3}',
    'port': r'\d{1,5}',
    'protocol': r'[A-Za-z0-9+/._-]+',
    'username': r'\S+',
    'path': r'\S+',
    'number': r'\d+',
    'time': r'\d{2}:\d{2}(?::\d{2})?',
    'text': r'.+',
}


def kind_to_regex(kind: str) -> str:
    return KIND_REGEX.get(kind, r'\S+')


def build_stage2_patterns(
    format_type: str,
    message_samples: List[str],
    llm_mappings: Optional[List[Dict]] = None,
) -> List[Dict]:
    """
    仅从 LLM 标注映射生成 Stage2 提取规则(无预置表)。

    Args:
        format_type: 格式类型名
        message_samples: message 样本(保留参数,供未来校验用)
        llm_mappings: LLM 标注输出,每项为 kv_key/token/keyword/裸值 形式之一

    Returns:
        [{"name","type","field_name","extract_method","kv_key"/"regex"}]
    """
    patterns: List[Dict] = []
    seen: set = set()

    def add(field: str, method: str, **kw):
        if field in seen:
            return
        seen.add(field)
        p = {
            'name': field,
            'type': format_type,
            'field_name': field,
            'extract_method': method,
        }
        p.update(kw)
        patterns.append(p)

    for m in (llm_mappings or []):
        field = m.get('field_name')
        if not field or field in seen:
            continue

        # message_content(告警信息)特殊规则:whole/键值/unknown 三种载体
        # (去重由循环开头 field in seen 与 add() 内 seen 检查共同保证)
        if field == 'message_content':
            if m.get('source') == 'whole':
                # 整个 message 就是告警信息(原文原样)
                add(field, 'message_content', source='whole')
            elif m.get('source') == 'unknown':
                # 不确定 → 输出整句 message,标注不确定
                add(field, 'message_content', source='unknown')
            elif m.get('kv_key'):
                # 告警信息在 KEY="VALUE" 字段的值里
                add(field, 'message_content', kv_key=m['kv_key'])
            elif m.get('json_key'):
                # 告警信息在 JSON 载荷的某个键里
                add(field, 'message_content', json_key=m['json_key'])
            continue

        kind = m.get('kind', 'text')
        value_re = kind_to_regex(kind)

        if m.get('inner') == 'pri':
            # 转发 syslog:priority/facility/severity 来自内层原始 syslog 的 <NN> 优先级标记
            # (在线由 extract_kv_parser 从 ORIGINAL_DATA 内层解析,规则仅作标注表达)
            add(field, 'inner_pri')
            continue
        if m.get('kv_key'):
            # KEY="VALUE" 形式
            add(field, 'kv_parse', kv_key=m['kv_key'])
        elif m.get('json_key'):
            # JSON 载荷键形式(工控平台类,如 dev_ip/dev_name/level)
            add(field, 'kv_parse', json_key=m['json_key'])
        elif m.get('token'):
            # 中文标签:值 形式
            token = re.escape(m['token'])
            if kind == 'ip' or kind == 'port' or kind == 'protocol':
                regex = rf'{token}[:：]?\s*({value_re})'
            elif field in ('severity', 'priority'):
                # severity/priority 必须是数字(防 LLM 把单词误标给这两个字段)
                regex = rf'{token}[:：]?\s*(\d+)'
            else:
                regex = rf'{token}[:：]?\s*(\S+)'
            add(field, 'regex', regex=regex)
        elif m.get('keyword'):
            # 英文引导词:值 形式(自由文本,如 "from 192.0.2.5"、"port 22"、"user=admin")
            keyword = re.escape(m['keyword'])
            if field in ('severity', 'priority'):
                regex = rf'\b{keyword}[=:\s]+\s*(\d+)'
            elif kind == 'ip':
                regex = rf'\b{keyword}[=:\s]+\s*({value_re})'
            elif kind == 'number' or kind == 'port':
                regex = rf'\b{keyword}[=:\s]+\s*(\d+)'
            elif kind == 'protocol':
                regex = rf'\b{keyword}[=:\s]+\s*({value_re})'
            else:
                regex = rf'\b{keyword}[=:\s]+\s*(\S+)'
            add(field, 'regex', regex=regex)
        else:
            # 裸值(无引导词):无法可靠定位,丢弃(避免全局误匹配,如 (\d+) 匹配任意数字)
            # 宁可漏提,不误报——有引导词的映射优先
            logger.debug(f"  [规则] 丢弃裸值映射: {field}(kind={kind}),无引导词无法可靠定位")
            continue

    return patterns
