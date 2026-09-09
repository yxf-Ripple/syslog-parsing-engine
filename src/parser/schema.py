#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
输出 schema 对齐层:内部解析结果 -> StandardizedEvent 兼容 JSON
----------------------------------------------------------------
对齐 example/data-ingestion-service 的 StandardizedEvent 字段形状
(键名/类型;枚举用字符串值,下游 StandardizedEvent(**data) 直接可构造)。

"未涉及字段"处理策略:
1. 有来源 -> 映射(如 username<-source_user, event_code<-event_id)
2. 无信息源(location/department/business_unit/application_name/event_subtype)
   -> 省略不输出,下游 pydantic 用默认值(None/"")
3. 系统生成(event_id 唯一标识/processing_time/parser_version)-> 本层填充
4. 全部内部字段 -> 打包进 parsed_content(信息不丢失)
"""
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

CST = timezone(timedelta(hours=8))

# 内部哨兵值(视为空,fallback 时才用下一候选)
_SENTINELS = (None, "unknown", "None", "N/A", "")


def _clean(val: Any) -> Any:
    """清洗哨兵值:unknown/None/N/A/空 -> None"""
    if val is None:
        return None
    s = str(val)
    return None if s in _SENTINELS else val

# event_type(内部值/关键词) -> StandardizedEvent.EventType 枚举名
_EVENT_TYPE_RULES = [
    (("security_audit", "audit_", "security-auditing", "审计", "安全"), "SECURITY_ALERT"),
    (("登录", "login", "auth", "认证", "logout"), "AUTHENTICATION"),
    (("非法报文", "攻击", "入侵", "alert", "拦截", "威胁"), "SECURITY_ALERT"),
    (("网络", "network", "packet", "mac", "端口", "报文"), "NETWORK_ALERT"),
    (("service_control", "error", "错误", "无法启动", "失败", "fail", "异常"), "SYSTEM_ERROR"),
    (("system", "系统", "服务", "startup", "shutdown", "config", "配置", "操作"), "SYSTEM_EVENT"),
]

# risk_level 内部值 -> RiskLevel 枚举名
_RISK_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


def _to_dt(val: Any) -> Optional[datetime]:
    """float 时间戳/ISO 字符串 -> CST datetime;解析失败返回 None"""
    if isinstance(val, (int, float)) and val > 0:
        return datetime.fromtimestamp(val, tz=CST)
    if isinstance(val, datetime):
        return val
    if isinstance(val, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(val, fmt)
            except ValueError:
                continue
    return None


def _to_int(val: Any) -> Optional[int]:
    """字符串/数字 -> int;非法返回 None"""
    if isinstance(val, bool):
        return None
    if isinstance(val, (int, float)):
        return int(val)
    if isinstance(val, str) and val.strip().isdigit():
        return int(val.strip())
    return None


def _map_device_type(val: Any) -> str:
    """对齐 example 的设备类型映射:Windows/Microsoft -> windows_server;含 OS -> operating_system;network -> network_device"""
    s = str(val or "")
    if not s or s in _SENTINELS:
        return ""
    if "Windows" in s or "Microsoft" in s:
        return "windows_server"
    if "OS" in s:
        return "operating_system"
    if "network" in s.lower():
        return "network_device"
    return s


def _infer_internal_event_type(parsed: Dict[str, Any]) -> Optional[str]:
    """对齐 example 的 Windows 事件映射:Security-Auditing -> security_audit, Service_Control_Manager -> service_control"""
    prog = str(parsed.get("program") or "")
    if not prog or prog in ("unknown", "None"):
        prog = str(parsed.get("module") or "")
    if not prog or prog in ("unknown", "None"):
        prog = str(parsed.get("dvc_event_category") or "")
    low = prog.lower()
    if "security-auditing" in low or "security" in low:
        return "security_audit"
    if "service_control" in low:
        return "service_control"
    return None


def _map_event_type(parsed: Dict[str, Any]) -> str:
    """内部 event_type/内容 -> EventType 枚举名(默认 UNKNOWN)"""
    et = str(parsed.get("event_type") or "").lower()
    if not et or et in ("unknown", "none"):
        inferred = _infer_internal_event_type(parsed)
        if inferred:
            et = inferred
    content = " ".join(str(parsed.get(k) or "") for k in
                       ("message_content", "dvc_event_category", "content", "_stage2_message")).lower()
    # 先按内部精确值匹配(security_audit/service_control 等,避免被 content 关键词抢占)
    if et:
        for keywords, enum_name in _EVENT_TYPE_RULES:
            if et in keywords:
                return enum_name
    for keywords, enum_name in _EVENT_TYPE_RULES:
        if any(k in content for k in keywords):
            return enum_name
    return "UNKNOWN"


def _map_risk_level(parsed: Dict[str, Any]) -> str:
    """risk_level/severity -> RiskLevel 枚举名(默认 INFO)"""
    rl = parsed.get("risk_level")
    if isinstance(rl, str) and rl.lower() in _RISK_MAP:
        return _RISK_MAP[rl.lower()]
    sev = parsed.get("severity")
    if isinstance(sev, int):
        if sev <= 1:
            return "CRITICAL"
        if sev == 2:
            return "HIGH"
        if sev == 3:
            return "MEDIUM"
        if sev == 4:
            return "LOW"
    return "INFO"


def to_standardized_event(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """
    内部解析结果 -> 最终输出 JSON(字段清单 = example 25 字段 + 有意义的附加字段,不重复)。
    - example 25 字段照输出(无论有无值;无值用空字符串占位,对齐 example 风格)
    - 附加字段只保留有意义的,且不与 example 字段重复
    - parsed_content 只保存 syslog 原始内容(整行)
    """
    now = datetime.now(CST)
    original_syslog = str(parsed.get("original_syslog") or parsed.get("raw_message") or "")
    message_content = str(_clean(parsed.get("message_content")) or _clean(parsed.get("content")) or "")
    raw_message = str(parsed.get("raw_message") or "") or message_content[:500]

    def s(key: str, fallback: str = "") -> str:
        v = _clean(parsed.get(key))
        if v is None:
            v = _clean(parsed.get(key.replace("source_device_", "device_")))  # source_* 回退 device_*
            if v is None and key == "source_device_name":
                v = _clean(parsed.get("hostname"))
        return str(v) if v else fallback

    # === example 25 字段(照输出) ===
    out: Dict[str, Any] = {
        "priority": _to_int(parsed.get("priority")) or 0,
        "facility": _to_int(parsed.get("facility")) or 0,
        "severity": _to_int(parsed.get("severity")) or 0,
        "timestamp": _to_dt(parsed.get("timestamp")) or now,
        "syslog_ip": s("syslog_ip"),
        "hostname": s("hostname"),
        "event_id": s("event_id") or s("event_code"),  # 原始事件 ID(对齐 example;LLM 标注常标 event_code←MSG_ID,回退承接)
        "device_ip": s("device_ip") or s("hostname"),  # 回退 hostname(对齐 example:BSD/纯文本格式无 IP)
        "device_name": s("device_name") or s("hostname"),
        "device_type": _map_device_type(parsed.get("device_type")),
        "source_device_ip": s("source_device_ip") or s("device_ip") or s("hostname"),
        "source_device_name": s("source_device_name") or s("device_name") or s("hostname"),
        "source_device_type": s("source_device_type") or s("device_type"),
        "structured_data": parsed.get("structured_data") or {},
        "original_data": s("original_data"),
        "message_content": message_content,              # 告警信息(全格式必提取,见决定栏)
        "raw_message": raw_message,                      # message_content 截断版
        "source_ip": s("source_ip"),
        "destination_user": s("destination_user"),
        "source_user": s("source_user"),
        "data_object_type": s("data_object_type"),
        "file_name": s("file_name"),
        "dvc_event_category": s("dvc_event_category"),
        "agent_address": s("agent_address"),
        # === 附加(有意义,不与 example 重复) ===
        "event_type": _map_event_type(parsed),           # 事件分类(枚举)
        "risk_level": _map_risk_level(parsed),           # 风险等级(枚举)
        "received_at": _to_dt(parsed.get("received_at")) or now,
        "parse_success": bool(parsed.get("parse_success")),
        "parse_errors": list(parsed.get("parse_errors") or []),
        "log_format": s("log_format") or "unknown",       # 格式类型(对齐 example,来自 stage1 pattern.format)
        "message_content_decision": parsed.get("message_content_decision") or "",
        "parsed_content": {"syslog": original_syslog},   # 只保存 syslog 原始内容
    }

    # 附加网络/用户字段(有值才输出;无则省略,不输出空占位)
    for k in ("username", "user_domain", "protocol", "destination_ip"):
        v = _clean(parsed.get(k))
        if v:
            out[k] = str(v)
    for k in ("source_port", "destination_port"):
        v = _to_int(parsed.get(k))
        if v is not None:
            out[k] = v

    return out
