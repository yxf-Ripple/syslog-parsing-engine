#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLM 字段标注器
--------------
LLM 不再写正则,只做字段语义标注:
给定某格式类型的 message 样本,输出"样本中哪些片段对应标准字段"。

输出:
{
  "mappings": [
    {"field_name": "source_ip", "token": "源地址", "kind": "ip"},
    {"field_name": "device_ip", "kv_key": "DVC_ADDRESS"}
  ]
}
- token: 样本中该字段的引导词(中文标签或 KV 键),用于构造提取正则
- kv_key: 若是 KEY="VALUE" 形式则给出 KEY
- kind: 值类型(ip/port/number/protocol/username/path/text)

翻译为 Stage2 规则由 src/parser/field_rules.build_stage2_patterns 完成。
"""
import re
from typing import Dict, List, Optional, Set, Tuple

from .llm_client import LLMClient
from ..utils.logger import setup_logger

logger = setup_logger("llm_annotator")

# 标准字段清单 = StandardizedEvent 对齐字段(用户只需要对齐数据模型里的这些字段)
# LLM 只在这份清单里标注,在 syslog 样本中定位这些字段对应的信息片段
STANDARD_FIELDS = (
    "device_ip, device_name, device_type, facility, severity, "
    "event_code, event_subtype, event_type, "
    "source_ip, destination_ip, source_port, destination_port, protocol, "
    "username, user_domain, application_name"
)

# 引导形式检测正则
_KV_KEY_RE = re.compile(r'\b([A-Z][A-Z0-9_]{2,})="')
# 中文标签:要求标签前是空白/行首(避免匹配内容里的中文短语);冒号后可有空格(标签: 值)
_CN_LABEL_RE = re.compile(r'(?<!\S)([\u4e00-\u9fff]{1,8})[:：]')
# 轻量 message 结构分组:前 3 token 的类型化签名
_SIG_TOKEN_RE = [
    (re.compile(r'\d{1,3}(\.\d{1,3}){3}'), '<IP>'),
    (re.compile(r'\d+'), '<NUM>'),
    (re.compile(r'[0-9a-fA-F]+'), '<HEX>'),
]

def detect_guidance_forms(messages: List[str], sample_limit: int = 500) -> Dict:
    """
    引导形式预检测(纯正则,零 LLM 成本):
    统计 message 中出现的 KEY=" 键集 / 中文标签集 / 自由文本占比,
    返回 verdict 决定 Stage2 标注策略:
      skip   - 纯自由文本,无引导形式,跳过 LLM 标注(message_content 兜底)
      stable - 引导形式键集小且稳定(≤8 种),少量样本即可覆盖
      mixed  - 引导形式种类多,需按 message 结构分组标注
    """
    sampled = messages[:sample_limit]
    kv_keys: Set[str] = set()
    cn_labels: Set[str] = set()
    n_free = 0
    line_sigs: Set[Tuple] = set()  # 每行出现的引导形式签名(排序元组)
    for m in sampled:
        kvs = set(_KV_KEY_RE.findall(m))
        cns = set(_CN_LABEL_RE.findall(m))
        kv_keys |= kvs
        cn_labels |= cns
        line_sigs.add(tuple(sorted(kvs | cns)))
        if not kvs and not cns:
            n_free += 1
    total = len(sampled) or 1
    free_ratio = n_free / total
    # KV 主导格式(KV 键 ≥2):中文"标签"多为 KV 值内部的内容噪声,字段结构由 KV 键决定
    kv_dominant = len(kv_keys) >= 2
    total_forms = len(kv_keys) if kv_dominant else len(cn_labels)
    # 行间签名也只看主导形式
    if kv_dominant:
        sigs = {tuple(sorted(set(_KV_KEY_RE.findall(m)))) for m in sampled}
    else:
        sigs = {tuple(sorted(set(_CN_LABEL_RE.findall(m)))) for m in sampled}
    n_line_sigs = len(sigs)
    # 所有格式都走 LLM 标注(普遍可行,自由文本也有可提取信息);仅用结构签名决定分组
    if n_line_sigs <= 4:
        # 行间结构一致(每行同一批键/标签/引导词),一次标注即可覆盖
        verdict = "stable"
    else:
        # 行间结构差异大(不同 message 类型各有引导形式),需分组标注
        verdict = "mixed"
    det = {
        "kv_keys": kv_keys,
        "cn_labels": cn_labels,
        "free_text_ratio": round(free_ratio, 3),
        "total_forms": total_forms,
        "n_line_sigs": n_line_sigs,
        "verdict": verdict,
    }
    logger.info(
        f"  [检测] 引导形式: {total_forms} 种 (kv_keys={len(kv_keys)}, cn_labels={len(cn_labels)}, "
        f"行间签名 {n_line_sigs} 种,自由文本占比 {free_ratio:.0%}) → {verdict}"
    )
    return det


def cluster_by_message_structure(messages: List[str], max_groups: int = 8) -> List[List[str]]:
    """按 message 前 3 token 的类型化签名轻量分组,每组返回样本列表"""
    groups: Dict[Tuple, List[str]] = {}
    for m in messages:
        sig = _message_sig(m)
        groups.setdefault(sig, []).append(m)
    # 按组大小降序,取前 max_groups 组(每组的引导形式代表整体)
    ordered = sorted(groups.values(), key=len, reverse=True)[:max_groups]
    return [g[:6] for g in ordered]


def _message_sig(msg: str) -> Tuple:
    toks = msg.split()[:3]
    parts = []
    for t in toks:
        matched = False
        for rx, tag in _SIG_TOKEN_RE:
            if rx.fullmatch(t):
                parts.append(tag)
                matched = True
                break
        if not matched:
            parts.append(t)
    return tuple(parts)


# 无需 LLM 标注的字段(由 Stage1/原始数据直接提供;message_content 除外,需 LLM 判断告警信息载体)
SKIP_FIELDS = {'original_data', 'raw_message'}
# 数值字段:标注的 kv_key 在样本中对应值必须是数字,否则丢弃(防 facility=FILE_NAME 类错误)
NUMERIC_FIELDS = {'facility', 'severity', 'priority'}
# token 过长视为整段过拟合,丢弃
MAX_TOKEN_LEN = 40


def _kv_value_is_numeric(samples: List[str], kv_key: str) -> bool:
    """检查样本中该键对应的值是否为数字,同时支持两种形态:
    - KV:  key="123"(天融信类,值可为带引号数字)
    - JSON: "key": 123(工控平台类,数字值不带引号;字符串值如 "13-1" 不算)
    """
    kv_pat = re.compile(rf'\b{re.escape(kv_key)}\s*=\s*"?(-?\d+)"?', re.I)
    json_pat = re.compile(rf'"{re.escape(kv_key)}"\s*:\s*(-?\d+)(?=[,}}\s]|$)', re.I)
    for s in samples:
        if kv_pat.search(s) or json_pat.search(s):
            return True
    return False


class LLMAnnotator:
    """LLM 字段标注器(只输出字段映射,不生成正则)"""

    def __init__(self):
        self.client = LLMClient()

    def annotate(self, format_type: str, samples: List[str], forwarded: bool = False) -> Optional[List[Dict]]:
        """标注样本字段,返回 mappings 列表(失败返回 None)

        Args:
            format_type: 格式类型名
            samples: message 样本
            forwarded: 是否转发 syslog(外层转发包装 + 内层被转发的原始 syslog),
                       由 detect_guidance_forms 预检测得出,true 时 prompt 加转发结构引导
        """
        if not samples:
            return None
        # 转发格式的 ORIGINAL_DATA(内层原始 syslog)在样本尾部,给更长截断避免 LLM 看不到内层 <NN>
        cut = 1200 if forwarded else 400
        samples_text = "\n".join(f"[{i+1}] {s[:cut]}" for i, s in enumerate(samples[:20]))
        forward_guide = ""
        if forwarded:
            forward_guide = (
                "重要:这些样本是【转发 syslog】——外层是转发包装(采集时间/转发源 IP/设备信息的 "
                "KEY=\"VALUE\" 字段),内层(如 ORIGINAL_DATA 等键的值)是被转发的原始 syslog。\n"
                "标注时遵循:\n"
                "- priority/facility/severity 是 syslog 协议字段,来自【内层原始 syslog 的 <NN> 优先级标记】,"
                "标注为 {\"field_name\":\"priority\",\"inner\":\"pri\"} / {\"field_name\":\"facility\",\"inner\":\"pri\"} / "
                "{\"field_name\":\"severity\",\"inner\":\"pri\"};\n"
                "  禁止把外层的 PRIORITY 键标成 severity/priority(那是厂商自定义优先级,不是 syslog 严重度);\n"
                "- 其他业务字段(device_ip/event_id/source_ip/username 等)按语义从外层 KEY=\"VALUE\" 字段或内层日志提取;\n"
                "- message_content 按内容语义判断(可能在 MESSAGE= 值或内层日志中),必须原文原样。\n\n"
            )
        prompt = f"""你是日志字段标注专家。给定 {format_type} 格式的日志 message 样本,
找出样本中出现的、与标准字段对应的信息片段。

标准字段(只从中选): {STANDARD_FIELDS}

任务:
1. 逐条样本,找出样本中出现的、对应标准字段的信息片段,给出字段值的"引导形式":
   - KEY="VALUE" 形式 → 给出 kv_key(如 DVC_ADDRESS)
   - 中文标签:值 形式 → 给出 token(如 源地址)
   - 英文引导词:值 形式(如 from 192.0.2.5、port 22、user=admin、account=)
     → 给出 keyword(如 from/port/user/account)
   - 找不到任何引导词的字段不要标注(避免无法定位的裸值)
2. 值类型 kind ∈ ip/port/number/protocol/username/path/time/text
3. 标注告警信息(message_content)的提取方式(每格式至多一条):
   - {{"field_name":"message_content","source":"whole"}} —— 整个 message 就是告警信息(原文原样)
   - {{"field_name":"message_content","kv_key":"MESSAGE"}} —— 告警信息在某个 KEY="VALUE" 字段的值里
     (键名可能是 MESSAGE、content、message-content 等任何形式,以样本实际为准)
   - {{"field_name":"message_content","json_key":"event_content"}} —— 告警信息在 JSON 载荷的某个键里
   - {{"field_name":"message_content","source":"unknown"}} —— 无法确定哪个是告警信息 → 输出整句 message,标注不确定

{forward_guide}规则:
- 字段名必须来自上面的标准字段清单
- 告警信息必须是原文一模一样,不做任何多余操作(不精炼、不裁剪、不截断)
- 绝对不可以根据前缀名(如 MESSAGE=、content=)判断它是不是告警信息,必须看内容语义
- facility/severity/priority 是数字字段,只能标注数字类来源(如 SEVERITY 键、数字引导词、或转发格式的内层 <NN>),禁止标注 FILE_NAME 这类非数字键
- 只输出样本中确实存在的字段,不存在的跳过
- 禁止逐条输出每条样本的字段值
- 只输出"引导形式"的并集,每种引导形式一条映射
- 不输出字段的值本身,不输出逐条样本的解析结果
- 不写正则,不写解释

只返回纯 JSON:
{{"mappings":[{{"field_name":"source_ip","token":"源地址","kind":"ip"}},{{"field_name":"device_ip","kv_key":"DVC_ADDRESS"}},{{"field_name":"message_content","source":"whole"}}]}}

样本({len(samples)}条):
{samples_text}"""
        result = self.client.call_json(prompt, max_retries=2)
        if not result or "mappings" not in result:
            logger.warning(f"  [标注] {format_type} 标注失败")
            return None
        mappings = result.get("mappings") or []
        # 过滤:跳过整段字段、过长 token
        filtered = []
        for m in mappings:
            f = m.get('field_name', '')
            tok = m.get('token', '')
            if f in SKIP_FIELDS or (not m.get('kv_key') and len(tok) > MAX_TOKEN_LEN):
                continue
            # 数值字段(facility/severity/priority):kv_key 在样本中对应值必须是数字
            if f in NUMERIC_FIELDS and m.get('kv_key'):
                if not _kv_value_is_numeric(samples, m['kv_key']):
                    logger.warning(f"  [标注] 丢弃数值字段错误映射: {f} <- {m['kv_key']}(样本值非数字)")
                    continue
            filtered.append(m)
        mappings = filtered
        logger.info(f"  [标注] {format_type}: {len(mappings)} 个字段映射")
        for m in mappings[:10]:
            logger.info(f"    - {m.get('field_name')}: {m.get('kv_key') or m.get('token')} ({m.get('kind','')})")
        return mappings

    def check_templates(self, templates: List[Dict]) -> Dict:
        """Drain 学出模板后,由 LLM 检查:哪些是噪音(明显非 syslog + count 特别少)+ 整体是否转发。

        返回 {"noise_names": List[str], "forwarded": bool}
        - 噪音模板由调用方删除(不进 stage1);判定严格,疑似 syslog 一律保留,不误伤正常数据
        - forwarded 供字段标注(转发 syslog 的 priority/severity 来自内层 <NN>)
        """
        if not templates:
            return {"noise_names": [], "forwarded": False}
        tpl_text = "\n".join(
            f"[{i+1}] 名称: {t.get('name', '')} | 出现次数: {t.get('count', '?')} | "
            f"样例: {(t.get('sample') or '')[:300]}"
            for i, t in enumerate(templates[:40])
        )
        prompt = f"""你是 syslog 日志模板审查专家。下面是自动聚类(Drain)刚学出的一批日志模板,
每个模板含:名称、出现次数(count)、样例。

任务:逐个模板判断它是"正常 syslog"还是"噪音"。

【噪音】必须同时满足以下明显特征才判定:
- 样例明显不是 syslog 形式:没有 <PRI> 优先级标记、没有时间戳、没有主机名/程序名、没有任何日志结构;
- 是孤立的词/短语/乱码(如"注销成功"这类),不是"某设备在什么时间做了什么"的日志;
- 出现次数极少(count ≤ 2)。

【绝对保护】只要样例疑似 syslog(哪怕格式没见过/很怪),一律算正常,不得判噪音;
拿不准的,不算噪音(宁可保留,不可误伤正常数据)。

另外判断:这批模板整体是不是【转发 syslog】
(外层是转发包装字段如采集时间/设备信息,内层某个字段的值是被转发的完整原始 syslog)。
非转发输出 false。

只返回纯 JSON(不解释):
{{"noise_names": ["噪音模板名称,无则空数组"], "forwarded": true或false}}

模板({len(templates)}个):
{tpl_text}"""
        try:
            result = self.client.call_json(prompt, max_retries=2)
        except Exception as e:
            logger.warning(f"  [检查模板] LLM 调用失败: {e}")
            return {"noise_names": [], "forwarded": False}
        if not result:
            logger.warning("  [检查模板] LLM 未返回结果,保守处理(不删任何模板)")
            return {"noise_names": [], "forwarded": False}
        noise = [str(n) for n in (result.get("noise_names") or [])]
        forwarded = bool(result.get("forwarded", False))
        logger.info(f"  [检查模板] {len(templates)} 个模板,判噪音 {len(noise)} 个,转发={forwarded}")
        if noise:
            logger.info(f"    噪音模板: {noise}")
        return {"noise_names": noise, "forwarded": forwarded}


def annotate_and_build_stage2(format_type: str, message_samples: List[str], forwarded: bool = False) -> List[Dict]:
    """
    LLM 标注(唯一字段语义来源,无预置规则)→ Stage2 patterns。
    按 message 结构检测分组:
      stable - 结构一致,一次标注
      mixed  - 结构多样,分组标注避免遗漏

    Args:
        forwarded: 是否转发 syslog(外层转发包装 + 内层被转发的原始 syslog),
                   由调用方(自动学习时 LLM 检查模板)判断得出
    """
    from .field_rules import build_stage2_patterns

    if not message_samples:
        return []

    # 引导形式预检测(纯正则,零 LLM 成本):只用于决定 stable/mixed 分组
    det = detect_guidance_forms(message_samples)

    annotator = LLMAnnotator()
    if det['verdict'] == 'mixed':
        # 结构多样:分组标注,合并映射(每组 ≤6 条)
        groups = cluster_by_message_structure(message_samples)
        logger.info(f"  [标注] {format_type}: mixed,按 message 结构分 {len(groups)} 组标注")
        for gi, g in enumerate(groups):
            m = annotator.annotate(f"{format_type}#g{gi+1}", g, forwarded=forwarded)
            if m:
                mappings.extend(m)
    else:
        mappings = annotator.annotate(format_type, message_samples, forwarded=forwarded) or []

    patterns = build_stage2_patterns(format_type, message_samples, llm_mappings=mappings)
    if not patterns:
        logger.warning(f"  [标注] {format_type}: LLM 标注未产出可用规则")
    return patterns
