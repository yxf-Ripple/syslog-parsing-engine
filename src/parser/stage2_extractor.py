#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
第二阶段提取器 - 从 message 内容中提取字段
支持两种提取方式:
- regex: 正则表达式提取
- kv_parse: 程序化 KV 解析 (KEY="VALUE" 格式)
"""
import json
import re
import yaml
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("stage2_extractor")


def _decode_unicode_escapes(s: str) -> str:
    """递归解码 \\uXXXX 转义(与 field_extractor 一致),供 message_content 等可读字段使用"""
    s = str(s)
    for _ in range(4):
        if r"\u" not in s and r"\r" not in s and r"\n" not in s and r"\t" not in s:
            break
        try:
            s = json.loads('"' + s.replace('"', '\\"') + '"')
        except Exception:
            break
    return s


class Stage2Pattern:
    """第二阶段模式(关联到 stage1 类型 + 来源格式 format)"""

    def __init__(
        self,
        name: str,
        regex: str = "",
        field_name: str = "",
        pattern_type: str = "",
        description: str = "",
        extract_method: str = "regex",
        kv_key: str = "",
        json_key: str = "",
        format: str = "",
        source: str = "",
    ):
        self.name = name
        self.regex = regex
        self.field_name = field_name
        self.pattern_type = pattern_type
        self.description = description
        self.extract_method = extract_method
        self.kv_key = kv_key
        self.json_key = json_key
        self.format = format
        self.source = source
        self.compiled_regex = re.compile(regex) if regex else None

    def match(self, message: str) -> Optional[str]:
        """尝试匹配 message 内容"""
        if self.extract_method == "inner_pri":
            # 转发 syslog 内层 PRI:由 extract_kv_parser 从 ORIGINAL_DATA 内层代码解析,
            # 规则仅作 LLM 标注表达,不在此重复提取
            return None
        if self.extract_method == "kv_parse":
            return self._extract_kv(message)
        return self._extract_regex(message)

    def _extract_regex(self, message: str) -> Optional[str]:
        """正则提取"""
        if not self.compiled_regex:
            return None
        m = self.compiled_regex.search(message)
        if m:
            return m.group(1) if m.groups() else m.group(0)
        return None

    def _extract_kv(self, message: str) -> Optional[str]:
        """程序化 KV 提取:
        1. json_key: 直接查 JSON 载荷的键(工控平台类,如 dev_ip/level)
        2. kv_key: message 内含 JSON 载荷 -> 该键查 dict;否则 KEY="VALUE" 格式(天融信类)
        """
        if self.json_key:
            m = re.search(r'\{.*\}$', message, re.S)
            if m:
                try:
                    data = json.loads(m.group(0))
                    if isinstance(data, dict) and data.get(self.json_key) is not None:
                        return str(data[self.json_key])
                except Exception:
                    pass
            return None
        if not self.kv_key:
            return None
        # JSON 载荷优先
        m = re.search(r'\{.*\}$', message, re.S)
        if m:
            try:
                data = json.loads(m.group(0))
                if isinstance(data, dict):
                    v = data.get(self.kv_key)
                    if v is None:
                        v = data.get(self.kv_key.lower())
                    if v is not None:
                        return str(v)
            except Exception:
                pass
        # 天融信式 KEY="VALUE"
        pattern = rf'{re.escape(self.kv_key)}="((?:[^"\\]|\\.)*)"'
        m = re.search(pattern, message)
        return m.group(1) if m else None


class Stage2Extractor:
    """第二阶段提取器 - 从 message 中提取字段（按 type 过滤）"""

    def __init__(self, patterns: List[Stage2Pattern] = None):
        self.patterns = patterns or []

    def extract(self, message: str, pattern_type: str = "", fmt: str = "") -> Dict[str, str]:
        """从 message 中提取字段(按 type + format 双键匹配)"""
        result = {}
        for pattern in self.patterns:
            if pattern_type and pattern.pattern_type and pattern.pattern_type != pattern_type:
                continue
            if fmt and pattern.format and pattern.format != fmt:
                continue
            if pattern.field_name == 'message_content':
                # message_content 规则由 extract_message_content 专用处理
                continue
            value = pattern.match(message)
            if value:
                result[pattern.field_name] = value
        return result

    def extract_message_content(self, message: str, pattern_type: str = "",
                                fmt: str = "") -> Tuple[Optional[str], str]:
        """按 LLM 标注的 message_content 规则提取告警信息(原文原样),返回 (content, decision)

        策略:同 type 下先尝试"具体载体"规则(json_key/kv_key),后尝试 whole/unknown——
        使含 JSON/KV 载荷的 message 命中其专属规则(如工控 event_content、udp MESSAGE),
        无载荷的 message(如 ag/3ji)回退 whole 整句。
        """
        def _match_fmt(p) -> bool:
            return (not fmt) or (not p.format) or (p.format == fmt)

        # 第一轮:具体载体规则(json_key / kv_key)
        for pattern in self.patterns:
            if pattern.field_name != 'message_content':
                continue
            if pattern_type and pattern.pattern_type and pattern.pattern_type != pattern_type:
                continue
            if not (pattern.json_key or pattern.kv_key):
                continue
            if not _match_fmt(pattern):
                continue
            if pattern.json_key:
                m = re.search(r'\{.*\}$', message, re.S)
                if m:
                    try:
                        data = json.loads(m.group(0))
                        if isinstance(data, dict) and data.get(pattern.json_key) is not None:
                            v = data[pattern.json_key]
                            return (_decode_unicode_escapes(str(v)),
                                    f"JSON 载荷 {pattern.json_key} 字段(LLM 标注)")
                    except Exception:
                        pass
            if pattern.kv_key:
                pm = re.search(rf'{re.escape(pattern.kv_key)}="((?:[^"\\]|\\.)*)"', message)
                if pm:
                    return (_decode_unicode_escapes(pm.group(1)),
                            f"KV 的 {pattern.kv_key} 字段(LLM 标注)")
        # 第二轮:whole / unknown(整句原文原样)
        for pattern in self.patterns:
            if pattern.field_name != 'message_content':
                continue
            if pattern_type and pattern.pattern_type and pattern.pattern_type != pattern_type:
                continue
            if not _match_fmt(pattern):
                continue
            if pattern.source == 'whole':
                return message, "整个 message 即告警信息(LLM 标注 whole)"
            if pattern.source == 'unknown':
                return message, "无法确定告警信息,输出整句 message(LLM 标注不确定)"
        return None, ""


def load_stage2_extractor(stage2_path: str = None) -> Stage2Extractor:
    """从 YAML 文件加载第二阶段提取器"""
    if stage2_path is None:
        stage2_path = str(Path(__file__).parent.parent.parent / "stage2_patterns.yaml")

    path = Path(stage2_path)
    if not path.exists():
        logger.warning(f"第二阶段模式文件不存在: {stage2_path}")
        return Stage2Extractor()

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    patterns = []
    for p in (data.get("patterns") or []):
        try:
            extract_method = p.get("extract_method", "regex")
            regex = p.get("regex", "")
            kv_key = p.get("kv_key", "")

            if extract_method == "kv_parse" and not kv_key and not p.get("json_key"):
                logger.warning(f"kv_parse 模式缺少 kv_key/json_key: {p.get('name', '?')}")
                continue
            if extract_method == "regex" and not regex:
                logger.warning(f"regex 模式缺少 regex: {p.get('name', '?')}")
                continue

            pattern = Stage2Pattern(
                name=p["name"],
                regex=regex,
                field_name=p.get("field_name", p["name"]),
                pattern_type=p.get("type", ""),
                description=p.get("description", ""),
                extract_method=extract_method,
                kv_key=kv_key,
                json_key=p.get("json_key", ""),
                format=p.get("format", ""),
                source=p.get("source", ""),
            )
            patterns.append(pattern)
        except KeyError as e:
            logger.error(f"模式定义缺少字段 {e}: {p.get('name', '?')}")
        except re.error as e:
            logger.error(f"正则编译失败 [{p.get('name', '?')}]: {e}")

    logger.info(f"已加载 {len(patterns)} 个第二阶段模式")
    return Stage2Extractor(patterns=patterns)
