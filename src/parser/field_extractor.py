"""
字段提取器 - 两阶段提取

阶段1: 提取 message 外的字段（timestamp、IP、hostname...）
阶段2: 提取 message 内的字段（通过 Stage2Extractor，支持 kv_parse 和 regex）
"""
import json
import re
import time
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from re import Match

from .stage2_extractor import load_stage2_extractor

logger = logging.getLogger("field_extractor")

_stage2_extractor = None


def _get_stage2_extractor():
    """获取全局 stage2 提取器（只加载一次）"""
    global _stage2_extractor
    if _stage2_extractor is None:
        _stage2_extractor = load_stage2_extractor()
    return _stage2_extractor


CST = timezone(timedelta(hours=8))

_BSD_TS_RE = re.compile(r'([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')


def _bsd_timestamp_from_raw(raw_message: str) -> Optional[float]:
    """从原始行兜底解析 BSD 风格时间(月 日 时:分:秒),失败返回 None"""
    m = _BSD_TS_RE.search(raw_message)
    if not m:
        return None
    for fmt in ["%b %d %H:%M:%S", "%b  %d %H:%M:%S"]:
        try:
            dt = datetime.strptime(m.group(1), fmt)
            if dt.year == 1900:
                dt = dt.replace(year=datetime.now(CST).year)
            return dt.timestamp()
        except ValueError:
            continue
    return None

DEVICE_TYPE_MAP = {
    2: "工控防火墙", 4: "主机安全卫士", 7: "日志审计系统",
    8: "入侵检测系统", 9: "工控安全隔离网关", 10: "工控网络安全监测平台",
    11: "USB隔离终端", 12: "全网诊断", 13: "工控防火墙-增强级", 0: "windows日志",
}


def _base_result(raw_message: str, syslog_ip: str = "unknown") -> Dict[str, Any]:
    """基础输出结构 - 所有字段默认 unknown"""
    return {
        "raw_message": raw_message,
        "original_syslog": raw_message,   # 原始整行 syslog(完整保留)
        "syslog_ip": syslog_ip,
        "received_at": time.time(),
        "parse_success": False,
        "parse_errors": [],
        "log_format": "unknown",
        "priority": "unknown",
        "facility": "unknown",
        "severity": "unknown",
        "timestamp": "unknown",
        "hostname": "unknown",
        "device_ip": "unknown",
        "device_name": "unknown",
        "device_type": "unknown",
        "source_device_ip": "unknown",
        "source_device_name": "unknown",
        "source_device_type": "unknown",
        "event_id": "unknown",
        "event_code": "unknown",
        "message_content": "unknown",
        "source_ip": "unknown",
        "destination_user": "unknown",
        "source_user": "unknown",
        "data_object_type": "unknown",
        "file_name": "unknown",
        "dvc_event_category": "unknown",
        "agent_address": "unknown",
        "structured_data": {},
        "original_data": "unknown",
        "module": "unknown",
        "event_type": "unknown",
        "content": "unknown",
        "risk_level": "unknown",
    }


def _parse_kv_pairs(message: str) -> Dict[str, str]:
    """通用 KV 解析:KEY="VALUE" -> {大写KEY: 值}(不依赖任何预置键表)"""
    pairs = {}
    for m in re.finditer(r'(\w+)="((?:[^"\\]|\\.)*)"', message or ""):
        pairs[m.group(1).upper()] = m.group(2).replace('\\"', '"').replace('\\\\', '\\')
    return pairs


def _decode_unicode_escapes(s: str) -> str:
    """
    递归解码 \\uXXXX 转义(兼容单/双重转义,如 13-1 的 \\u7528 与 0-2 的 \\\\u4e8b)。
    目的:message_content 等"给人看"的字段统一为真实中文/可读文本。
    内容含非法 \\u 序列时解码失败,保留原样。
    """
    s = str(s)
    for _ in range(4):
        if r"\u" not in s and r"\r" not in s and r"\n" not in s and r"\t" not in s:
            break
        try:
            s = json.loads('"' + s.replace('"', '\\"') + '"')
        except Exception:
            break
    return s


def _decide_message_content(message: str, raw_message: str):
    """
    自动决定 message_content(告警信息)的来源,返回 (content, decision)。
    按通用内容特征判断,不针对具体格式硬编码:
      1. message 内含 JSON 载荷且带 event_content 键 -> 取该值(工控平台类)
      2. 其余情况:message 组本身即告警描述(3ji/安管/BSD 等)
      3. 无法判断/取不到 -> message_content = 整条 message,标注"请人工确认"
    """
    msg = str(message or "").strip()
    if not msg:
        return (_decode_unicode_escapes(raw_message), "无法自动决定,已回退整条 message,请人工确认")
    # JSON 载荷(可能是 "- - - - {json}" 形式)
    if "{" in msg:
        m = re.search(r'\{.*\}$', msg, re.S)
        if m:
            try:
                data = json.loads(m.group(0))
                if isinstance(data, dict) and data.get("event_content"):
                    return (_decode_unicode_escapes(str(data["event_content"])), "JSON 载荷 event_content 字段")
            except Exception:
                pass
    return (_decode_unicode_escapes(msg), "message 组内容(告警描述)")


def _truncate_alert(message: str, limit: int = 500) -> str:
    """告警信息截断版(对齐 example):message_content[:500] + '...'(超长时)"""
    s = str(message or "")
    return s[:limit] + ('...' if len(s) > limit else '')


def _parse_timestamp(ts_str: str) -> float:
    """解析时间戳"""
    ts_str = ts_str.strip()
    for fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z"]:
        try:
            return datetime.strptime(ts_str, fmt).timestamp()
        except ValueError:
            continue
    for fmt in ["%b %d %H:%M:%S", "%b  %d %H:%M:%S"]:
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.year == 1900:
                dt = dt.replace(year=datetime.now(CST).year)
            return dt.timestamp()
        except ValueError:
            continue
    return time.time()


def _calculate_risk_level(severity: int) -> str:
    """计算风险等级"""
    if severity <= 1:
        return "critical"
    elif severity == 2:
        return "high"
    elif severity == 3:
        return "medium"
    elif severity == 4:
        return "low"
    elif severity == 5:
        return "info"
    else:
        return "info"


# 转发 syslog 内层原始日志的 PRI 标记:<NN>
_INNER_PRI_RE = re.compile(r'<(\d{1,3})>')


def _parse_priority_from_original_data(original_data: str) -> Optional[tuple]:
    """从转发 syslog 的 ORIGINAL_DATA(内层原始 syslog)提取 <NN> PRI(对齐 example)。

    返回 (priority, facility, severity),内层无 <NN> 时返回 None。
    facility = priority // 8,severity = priority % 8(syslog PRI 定义)。
    """
    if not original_data:
        return None
    m = _INNER_PRI_RE.search(original_data)
    if not m:
        return None
    try:
        pri = int(m.group(1))
    except (ValueError, TypeError):
        return None
    return pri, pri // 8, pri % 8


def extract_kv_parser(match: Match, raw_message: str, syslog_ip: str) -> Dict[str, Any]:
    """KV 对格式 - 带头部（时间 IP）+ message（KV 对，由 Stage2 处理）"""
    result = _base_result(raw_message, syslog_ip)
    result["log_format"] = "kv_structured"

    group_dict = match.groupdict()
    timestamp_str = group_dict.get("timestamp", "")
    header_ip = group_dict.get("ip") or group_dict.get("source_ip", "")
    message = group_dict.get("message", "")

    timestamp = time.time()
    if timestamp_str:
        for fmt in ["%b %d %H:%M:%S", "%b  %d %H:%M:%S"]:
            try:
                dt = datetime.strptime(timestamp_str.strip(), fmt)
                if dt.year == 1900:
                    dt = dt.replace(year=datetime.now(CST).year)
                timestamp = dt.timestamp()
                break
            except ValueError:
                continue
    else:
        # 正则未捕获完整时间时,从原始行兜底 BSD 时间
        bs = _bsd_timestamp_from_raw(raw_message)
        if bs:
            timestamp = bs

    result.update({
        "parse_success": True,
        "timestamp": timestamp,
        "message_content": message,
        # Stage2 输入:完整 KV 段(message_content 已是 MESSAGE 值,不能用于提取 KV 键)
        "_stage2_message": message,
    })

    if header_ip:
        result["syslog_ip"] = header_ip

    # 通用 KV 解析(不依赖预置键表):MESSAGE -> 告警信息,ORIGINAL_DATA -> 原始词条
    # 其余 KV 键由 Stage2 的 LLM 标注规则提取
    if message:
        kv = _parse_kv_pairs(message)
        mc = kv.get("MESSAGE")
        if mc:
            mc = _decode_unicode_escapes(mc)
            result["message_content"] = mc
            result["content"] = mc
            result["raw_message"] = _truncate_alert(mc)
            result["message_content_decision"] = "KV 的 MESSAGE 字段"
        else:
            # 无 MESSAGE 键:无法自动判断告警信息,回退整条 message 请人工确认
            result["message_content"] = message
            result["raw_message"] = _truncate_alert(message)
            result["message_content_decision"] = "无法自动决定,已回退整条 message,请人工确认"
        od = kv.get("ORIGINAL_DATA")
        if od:
            result["original_data"] = od
            # 转发 syslog:从内层原始 syslog 解析 <NN> PRI -> priority/facility/severity(对齐 example)
            pri_info = _parse_priority_from_original_data(od)
            if pri_info:
                result["priority"], result["facility"], result["severity"] = pri_info
        # SEVERITY 键覆盖 severity(对齐 example _fill_parsed_from_structured_fields)
        sev_val = kv.get("SEVERITY")
        if sev_val and str(sev_val).strip().lstrip("-").isdigit():
            result["severity"] = int(sev_val)

    return result


def extract_rfc5424_json(match: Match, raw_message: str, syslog_ip: str) -> Dict[str, Any]:
    """RFC5424 JSON 格式"""
    result = _base_result(raw_message, syslog_ip)
    result["log_format"] = "rfc5424_json"

    priority = int(match.group("priority"))
    facility = priority // 8
    severity = priority % 8
    timestamp_str = match.group("timestamp")
    hostname = match.group("hostname")
    json_msg = match.group("json_msg")

    timestamp = _parse_timestamp(timestamp_str)

    result.update({
        "parse_success": True,
        "priority": priority,
        "facility": facility,
        "severity": severity,
        "timestamp": timestamp,
        "hostname": hostname,
        "message_content": json_msg,
        "original_data": json_msg,
        "structured_data": {"json_msg": json_msg},
    })

    return result


def extract_rfc5424_plain(match: Match, raw_message: str, syslog_ip: str) -> Dict[str, Any]:
    """RFC5424 纯文本格式"""
    result = _base_result(raw_message, syslog_ip)
    result["log_format"] = "rfc5424_plain"

    group_dict = match.groupdict()

    priority = 0
    if "priority" in group_dict:
        priority = int(group_dict["priority"])
    else:
        pri_match = re.match(r"<(\d+)>", raw_message)
        if pri_match:
            priority = int(pri_match.group(1))

    facility = priority // 8
    severity = priority % 8
    timestamp_str = group_dict.get("timestamp", "")
    hostname = group_dict.get("hostname", "")
    message = group_dict.get("message", "")

    timestamp = _parse_timestamp(timestamp_str)

    result.update({
        "parse_success": True,
        "priority": priority,
        "facility": facility,
        "severity": severity,
        "timestamp": timestamp,
        "hostname": hostname,
        # message_content = 告警信息(全格式必提取):自动决定来源
        "message_content": message,
        "raw_message": _truncate_alert(message),
        "message_content_decision": "message 组内容(告警描述)",
        "_stage2_message": message,
    })

    return result


def extract_windows_event(match: Match, raw_message: str, syslog_ip: str) -> Dict[str, Any]:
    """Windows 事件格式"""
    result = _base_result(raw_message, syslog_ip)
    result["log_format"] = "windows_event"

    priority = int(match.group("priority"))
    facility = priority // 8
    severity = priority % 8
    timestamp_str = match.group("timestamp")
    hostname = match.group("hostname")
    event_source = match.group("program")
    event_id = match.group("event_id")
    content = match.group("message")

    timestamp = _parse_timestamp(timestamp_str)
    # 若正则只捕获到时:分:秒(无月日),从原始行兜底 BSD 完整时间
    if not re.match(r'[A-Za-z]{3}', str(timestamp_str).strip()):
        bs = _bsd_timestamp_from_raw(raw_message)
        if bs:
            timestamp = bs

    event_type = "unknown"
    if "Service_Control_Manager" in event_source:
        event_type = "service_control"
    elif "Security-Auditing" in event_source:
        event_type = "security_audit"

    result.update({
        "parse_success": True,
        "priority": priority,
        "facility": facility,
        "severity": severity,
        "timestamp": timestamp,
        "hostname": hostname,
        "event_id": int(event_id),
        "event_type": event_type,
        "content": content.strip(),
        "message_content": content.strip(),
        "raw_message": _truncate_alert(content),
        "message_content_decision": "message 组内容(告警描述)",
        "module": event_source,
        "risk_level": _calculate_risk_level(severity),
    })
    return result


def extract_generic(match: Match, raw_message: str, syslog_ip: str) -> Dict[str, Any]:
    """通用提取（兜底）:读取命名组填入对应字段(priority/timestamp/hostname/event_id/source_ip/program)"""
    result = _base_result(raw_message, syslog_ip)
    result["log_format"] = "generic"

    group_dict = match.groupdict()
    message = group_dict.get("message", raw_message)

    # 命名组 -> 字段(通用映射)
    ts = group_dict.get("timestamp")
    if ts:
        # BSD 纯时间(HH:MM:SS)缺月日无法解析,从原始行补全 "月 日 HH:MM:SS"
        if re.fullmatch(r'\d{2}:\d{2}:\d{2}(?:\.\d+)?', str(ts)):
            m = re.search(r'(?:<\d+>\s*)?([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})', raw_message)
            if m:
                ts = f"{m.group(1)} {m.group(2)} {m.group(3)}"
        result["timestamp"] = _parse_timestamp(ts)
    for key in ("priority", "severity"):
        if key in group_dict and group_dict[key] is not None:
            try:
                result[key] = int(group_dict[key])
            except ValueError:
                pass
    if result.get("priority") != "unknown":
        result["facility"] = int(result["priority"]) // 8
        if result.get("severity") == "unknown":
            result["severity"] = int(result["priority"]) % 8
    if group_dict.get("hostname"):
        result["hostname"] = group_dict["hostname"]
    if group_dict.get("event_id"):
        result["event_id"] = group_dict["event_id"]
    if group_dict.get("source_ip"):
        result["source_ip"] = group_dict["source_ip"]
    if group_dict.get("program"):
        result["dvc_event_category"] = group_dict["program"]

    # PRI 兜底(正则无命名组时从原始行提取)
    if result.get("priority") == "unknown":
        pri_match = re.match(r"<(\d+)>", raw_message)
        if pri_match:
            priority = int(pri_match.group(1))
            result["priority"] = priority
            result["facility"] = priority // 8
            result["severity"] = priority % 8

    result.update({
        "parse_success": True,
    })
    # message_content = 告警信息(全格式必提取):自动决定来源,无法决定则整条 message 请人工确认
    content, decision = _decide_message_content(message, raw_message)
    result["message_content"] = content
    result["content"] = content
    result["raw_message"] = _truncate_alert(content)
    result["message_content_decision"] = decision
    result["_stage2_message"] = message
    return result


EXTRACTORS = {
    "kv_parser": extract_kv_parser,
    "rfc5424_json": extract_rfc5424_json,
    "rfc5424_plain": extract_rfc5424_plain,
    "ip_prefix_syslog": extract_windows_event,
    "generic": extract_generic,
}


def extract(match: Match, extractor_type: str, raw_message: str, syslog_ip: str = "unknown",
            pattern_name: str = "", pattern_format: str = "") -> Dict[str, Any]:
    """两阶段提取：阶段1提取外层字段，阶段2通过 Stage2Extractor 提取 message 内字段

    pattern_format: stage1 pattern 的 format 字段(对齐 example log_format 类型)；
                   非空时覆盖 extractor 内置的 log_format,保证输出字段与 example 一致。
    """
    func = EXTRACTORS.get(extractor_type, extract_generic)
    try:
        # 阶段1：提取外层字段
        result = func(match, raw_message, syslog_ip)

        # log_format:优先 stage1 pattern 的 format(example 旧解析器类型)
        if pattern_format:
            result["log_format"] = pattern_format

        # 阶段2：通过 Stage2Extractor 从 message 中提取内部字段
        # 输入 = 原始 message 组(ag 等无 message_content 的格式用 _stage2_message,不受截断影响)
        message = result.get("_stage2_message") or result.get("message_content", "")
        # _stage2_message 保留在 result(进 parsed_content),供 event_type 判断等复用
        if message and message != "unknown":
            stage2 = _get_stage2_extractor()
            inner_fields = stage2.extract(message, pattern_type=pattern_name)
            for key, value in inner_fields.items():
                result[key] = value

            # message_content(告警信息):优先用 LLM 标注规则(原文一模一样,不做多余操作);
            # 无规则/提取失败则保留提取器默认(自动决定)
            mc_content, mc_decision = stage2.extract_message_content(message, pattern_type=pattern_name)
            if mc_content is not None:
                result["message_content"] = mc_content
                result["message_content_decision"] = mc_decision

            # 同步派生字段
            _sync_derived_fields(result)

        # log_format 按行细化(RFC5424 家族共享一个 stage1 pattern,JSON/纯文本无法在
        # pattern 层区分):message 尾部为 JSON 对象 -> rfc5424_json,否则纯文本 -> generic。
        # 工控 JSON 与安管纯文本同正则,pattern.format 只能二选一,故按行判定。
        lf = result.get("log_format") or pattern_format
        if lf in ("rfc5424_json", "generic"):
            msg = result.get("_stage2_message") or result.get("message_content", "") or raw_message
            mj = re.search(r'\{.*\}$', msg, re.S) if msg else None
            is_json = False
            if mj:
                try:
                    is_json = isinstance(json.loads(mj.group(0)), dict)
                except Exception:
                    is_json = False
            result["log_format"] = "rfc5424_json" if is_json else "generic"

        return result
    except Exception as e:
        logger.error(f"字段提取失败 [{extractor_type}]: {e}")
        result = _base_result(raw_message, syslog_ip)
        result["parse_errors"].append(f"字段提取异常: {e}")
        return result


def _sync_derived_fields(result: Dict[str, Any]):
    """同步派生字段"""
    if result.get("device_name") and result.get("device_name") != "unknown":
        result["hostname"] = result["device_name"]

    if result.get("device_ip") and result.get("device_ip") != "unknown":
        result["source_device_ip"] = result["device_ip"]

    if result.get("device_name") and result.get("device_name") != "unknown":
        result["source_device_name"] = result["device_name"]

    if result.get("device_type") and result.get("device_type") != "unknown":
        result["source_device_type"] = result["device_type"]

    if result.get("event_id") and result.get("event_id") != "unknown":
        result["event_code"] = result["event_id"]

    dvc_type = result.get("device_type", "unknown")
    if dvc_type and dvc_type != "unknown":
        if "Windows" in str(dvc_type) or "Microsoft" in str(dvc_type):
            result["device_type"] = "windows_server"
        elif "OS" in str(dvc_type):
            result["device_type"] = "operating_system"
        elif "network" in str(dvc_type).lower():
            result["device_type"] = "network_device"
