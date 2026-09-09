#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
嵌套 syslog 剥壳(附加功能,默认关闭,不影响现有输出)
----------------------------------------------------
背景:有些日志的 message 里转发了完整的内层 syslog
(如天融信 ORIGINAL_DATA="<29>Apr  2 09:31:05 30ES03151 Security-Auditing: 4663: ...")。

开启后:对原始行中的嵌套候选(original_data / message_content 值),
若满足"完整 syslog 形态"(PRI + 时间戳 + hostname),用现有模式库递归解析,
结果附加到输出 structured_data.nested_syslog;**不修改任何现有顶层字段**。

递归带 MAX_DEPTH 防环(嵌套的嵌套)。
"""
import re
from typing import Any, Dict, List, Optional

from .pattern_loader import PatternLoader
from .field_extractor import extract
from .schema import to_standardized_event

MAX_DEPTH = 3

# 嵌套 syslog 形态:<PRI> + (BSD 时间 | ISO 时间) + hostname
_NESTED_RE = re.compile(
    r'^\s*<\d+>'
    r'(?:\d+\s+)?'                       # RFC5424 版本号(可选)
    r'(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'  # ISO 时间
    r'|[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'  # BSD 时间
    r'\s+\S+'                            # hostname
)

# 嵌套候选来源字段(内部解析结果中可能含完整 syslog 的字段)
_CANDIDATE_KEYS = ("original_data", "message_content")


def detect_nested_syslog(text: str) -> bool:
    """判断文本是否为完整 syslog 形态(有 PRI + 时间戳 + hostname)"""
    if not text or not isinstance(text, str):
        return False
    return bool(_NESTED_RE.match(text))


def parse_nested(text: str, loader: PatternLoader, depth: int = 0) -> Optional[Dict[str, Any]]:
    """递归解析一段完整 syslog,返回 StandardizedEvent 兼容 dict(失败 None)"""
    if depth > MAX_DEPTH:
        return None
    text = text.strip()
    m = loader.match(text)
    if not m:
        # 空格归一化重试:BSD 格式有单/双空格对齐变体(如 Apr  2 vs Jun 19)
        normalized = re.sub(r'\s+', ' ', text)
        if normalized != text:
            m = loader.match(normalized)
            if m:
                text = normalized
    if not m:
        return None
    name, mo, ext, fmt = m
    parsed = extract(mo, ext, text, pattern_name=name, pattern_format=fmt)
    std = to_standardized_event(parsed)
    # 内层再嵌套(如 message 里又转发了一层)
    inner = extract_nested(parsed, loader, depth + 1)
    if inner:
        std.setdefault("structured_data", {})["nested_syslog"] = inner
    return std


def extract_nested(parsed: Dict[str, Any], loader: PatternLoader, depth: int = 0) -> Optional[Any]:
    """
    从内部解析结果提取嵌套 syslog(对每个候选值递归解析)。
    返回:单个 dict / dict 列表(多个候选) / None(无嵌套)
    """
    if depth > MAX_DEPTH:
        return None
    candidates: List[str] = []
    for k in _CANDIDATE_KEYS:
        v = parsed.get(k)
        if isinstance(v, str) and len(v) > 20 and detect_nested_syslog(v):
            if v not in candidates:
                candidates.append(v)
    if not candidates:
        return None
    results: List[Dict[str, Any]] = []
    for c in candidates[:2]:  # 最多解析前 2 个候选,防异常膨胀
        inner = parse_nested(c, loader, depth + 1)
        if inner:
            results.append(inner)
    if not results:
        return None
    return results[0] if len(results) == 1 else results


def attach_nested(parsed: Dict[str, Any], loader: PatternLoader, out: Dict[str, Any]) -> Dict[str, Any]:
    """
    附加嵌套解析结果到输出(不修改现有字段,也不污染传入的 out)。
    用法: out = to_standardized_event(parsed); out = attach_nested(parsed, loader, out)
    """
    nested = extract_nested(parsed, loader)
    if nested:
        sd = dict(out.get("structured_data") or {})
        sd["nested_syslog"] = nested
        out["structured_data"] = sd
    return out
