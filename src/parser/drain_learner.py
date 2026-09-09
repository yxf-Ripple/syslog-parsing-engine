#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
标准 Drain 模板学习器(离线)
--------------------------------
实现论文 "Drain: An Online Log Parsing Approach with Fixed Depth Tree" 的核心结构:
- 固定深度前缀树:按 token 类型(数字/IP/时间/普通词)构建前 MAX_PREFIX 层路径
- 叶子节点:模板列表,叶子内做序列相似度比较(仅前 MAX_PREFIX 个 token)
- 命中则合并模板(不同位置 -> <*>),未命中则新建模板

产出:模板列表(常量/变量 token 序列),可确定性泛化为 Stage1 正则
    ^<头部固定部分>(?P<message>.+)$
    - 头部:最后一个常量 token 之前的 token 序列(常量转义、变量按类型化正则)
    - 剩余:全部收进 (?P<message>.+)
仅用于离线学习;在线解析不依赖本模块(在线用预编译正则)。

设计要点(相对旧 log废弃/logg222222 实现的修正):
- 匹配复杂度 O(树深度),不是线性扫描全部模板
- 树路径按 token 分类键(数字统一为 <NUM> 等),提升聚类命中
- 相似度只比较前 MAX_PREFIX 个 token,长 message 也能聚到同一类
"""
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

# 树深度(比较前 N 个 token 决定类别;N 之后全部视为 message 内容)
MAX_PREFIX = 6
# 叶子内相似度阈值:前 MAX_PREFIX 个 token 的相同比例
SIM_THRESHOLD = 0.8
# 单条日志最多 token 数(防超长行)
MAX_TOKENS = 64

# ---------- token 分类 ----------

_NUM_RE = re.compile(r'^\d+$')
_FLOAT_RE = re.compile(r'^\d+(?:\.\d+)?$')
_IP_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
_TIME_RE = re.compile(r'^\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?$')
_ISO_TIME_RE = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}')
_PRI_RE = re.compile(r'^<\d+>$')
_PRI_VER_RE = re.compile(r'^<\d+>\d+$')  # RFC5424: <25>1 连写
_PRI_WORD_RE = re.compile(r'^<\d+>\w+$')  # BSD: <27>Jun 连写
_HEX_RE = re.compile(r'^0x[0-9a-fA-F]+$')
# KV 键 token: KEY="... "(值可为含空格未闭合,如 START_TIME="Thu Apr 02 ...")
_KV_TOKEN_RE = re.compile(r'^([A-Z][A-Z0-9_]{2,})="')


def is_var(tok: str) -> bool:
    """是否为变量 token(模板内变量统一标记为 <*>)"""
    return tok == '<*>'


# 强制变量化的类型化 token 分类键
_FORCE_VAR_CLASSES = ('<PRI>', '<IP>', '<ISOTIME>', '<TIME>', '<HEX>', '<NUM>')


def force_var(tok: str) -> bool:
    """
    判定 token 是否应强制变量化(即使样本中恰好相同):
    - 类型化 token(PRI/数字/时间/IP/HEX):值必然变化(日期、端口、PRI 等)
    - 含数字的混合串(4656:、DVC01、HOST01):设备名/事件ID 等可变值
    仅无数字的格式词(Security-Auditing: / Jun / - / KEY=)保留常量。
    """
    if is_var(tok):
        return True
    if classify_token(tok) in _FORCE_VAR_CLASSES:
        return True
    return bool(re.search(r'\d', tok))


# 有界枚举:月份/星期(有限集合,枚举化既不失配又保留特异性)
_MONTHS = {'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'}
_WEEKDAYS = {'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'}
_MONTH_RE = r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)'
_WEEKDAY_RE = r'(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)'

# 有界枚举:日志级别(带方括号形式,如 Apache [notice]/[error]/[warn])
_LEVELS_RE = r'\[(?:notice|error|warn|warning|debug|info|crit|critical|alert|emerg|emergency|verbose|none)\]'
_LEVEL_TOKEN_RE = re.compile(r'\[(?:notice|error|warn|warning|debug|info|crit|critical|alert|emerg|emergency|verbose|none)\]$')
# 连写星期 token(如 Apache "[Sat Jun 11 ...]" 的 "[Sat")
_BRACKET_WEEKDAY_RE = re.compile(r'\[(Mon|Tue|Wed|Thu|Fri|Sat|Sun)$')


def classify_token(tok: str) -> str:
    """返回 token 的分类键(用于树路径)。带缓存:token 值空间重复率高,加速学习。"""
    cached = _CLASSIFY_CACHE.get(tok)
    if cached is not None:
        return cached
    result = _classify_token_uncached(tok)
    _CLASSIFY_CACHE[tok] = result
    return result


_CLASSIFY_CACHE: Dict[str, str] = {}


def _classify_token_uncached(tok: str) -> str:
    """返回 token 的分类键(用于树路径)"""
    if _PRI_RE.match(tok) or _PRI_VER_RE.match(tok) or _PRI_WORD_RE.match(tok):
        return '<PRI>'
    if _IP_RE.match(tok):
        return '<IP>'
    if _ISO_TIME_RE.match(tok):
        return '<ISOTIME>'
    if _TIME_RE.match(tok):
        return '<TIME>'
    if _HEX_RE.match(tok):
        return '<HEX>'
    if _FLOAT_RE.match(tok):
        return '<NUM>'
    if _NUM_RE.match(tok):
        return '<NUM>'
    if tok.isalpha():
        return '<WORD>'
    m = _KV_TOKEN_RE.match(tok)
    if m:
        # KV 键 token:按 KEY 名分类(值不同也同类),如 DVC_ADDRESS="x" 与 DVC_ADDRESS="y"
        return f'KV:{m.group(1)}'
    return '<OTHER>'


def var_type_regex(tok: str) -> str:
    """变量 token 的类型化正则(提高特异性)。KV 键 token 保留 KEY 锚点(结构化泛化)。"""
    kv = _KV_TOKEN_RE.match(tok or '')
    if kv:
        # DVC_ADDRESS="x" -> DVC_ADDRESS="\S+ (保留 KEY,值泛化;兼容值含空格未闭合的 token)
        return re.escape(kv.group(1)) + r'="\S+'
    if _PRI_RE.match(tok) or _PRI_VER_RE.match(tok) or _PRI_WORD_RE.match(tok):
        if _PRI_VER_RE.match(tok):
            return r'<\d+>\d+'
        if _PRI_WORD_RE.match(tok):
            return r'<\d+>\w+'
        return r'<\d+>'
    if _IP_RE.match(tok):
        return r'\d{1,3}(?:\.\d{1,3}){3}'
    if _ISO_TIME_RE.match(tok):
        return r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?'
    if _TIME_RE.match(tok):
        return r'\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?'
    if _HEX_RE.match(tok):
        return r'0x[0-9a-fA-F]+'
    if _NUM_RE.match(tok):
        return r'\d+'
    return r'\S+'


@dataclass
class Template:
    """一个聚类模板"""
    tokens: List[str]                 # 常量/变量 token 序列,变量标记为 <*>
    seps: List[str] = field(default_factory=list)   # token 间分隔符序列(len = len(tokens)-1)
    count: int = 1
    samples: List[str] = field(default_factory=list)

    def last_const_index(self) -> int:
        """最后一个常量 token 的下标;全变量返回 -1"""
        for i in range(len(self.tokens) - 1, -1, -1):
            if not is_var(self.tokens[i]):
                return i
        return -1


class DrainLearner:
    """固定深度前缀树 Drain"""

    def __init__(self, max_prefix: int = MAX_PREFIX, sim_threshold: float = SIM_THRESHOLD):
        self.max_prefix = max_prefix
        self.sim_threshold = sim_threshold
        self.root: Dict = {}           # 树: {key: node}
        self.templates: List[Template] = []

    # ---------- token 化 ----------

    @staticmethod
    def tokenize(line: str) -> Tuple[List[str], List[str]]:
        """按空白切分,返回 (tokens, 分隔符序列)"""
        parts = re.split(r'(\s+)', line.strip())
        tokens, seps = [], []
        for i, p in enumerate(parts):
            if not p:
                continue
            if re.match(r'^\s+$', p):
                seps.append(p)
            else:
                tokens.append(p)
        # 分隔符数应为 tokens-1;补齐(极少数畸形行)
        while len(seps) < len(tokens) - 1:
            seps.append(' ')
        return tokens[:MAX_TOKENS], seps[:MAX_TOKENS - 1]

    # ---------- 树操作 ----------

    def _tree_path_keys(self, tokens: List[str]) -> List[str]:
        """前 max_prefix 个 token 的分类键序列"""
        return [classify_token(t) for t in tokens[:self.max_prefix]]

    def _similarity(self, tokens: List[str], tpl_tokens: List[str]) -> float:
        """前 max_prefix 个 token 的相同率
        规则:完全相等 / 同为变量 / 分类键相同的结构化 token(数字/时间/IP/优先级)都算匹配;
        普通词(WORD)与 OTHER 必须精确相等,避免把不同语义的固定词合并。
        """
        n = min(self.max_prefix, len(tokens), len(tpl_tokens))
        if n == 0:
            return 0.0
        same = 0
        for a, b in zip(tokens[:n], tpl_tokens[:n]):
            a_var, b_var = is_var(a), is_var(b)
            if a == b or (a_var and b_var):
                same += 1
            elif not a_var and not b_var:
                ca, cb = classify_token(a), classify_token(b)
                if ca == cb and ca not in ('<WORD>', '<OTHER>'):
                    same += 1
        return same / n

    def _merge(self, tokens: List[str], seps: List[str], tpl: Template):
        """把 tokens 合并进模板(逐位置泛化)"""
        tpl.count += 1
        # 扩展 tokens(模板可能更短)
        while len(tpl.tokens) < len(tokens):
            tpl.tokens.append('<*>')
        # 逐位置合并:不同 -> <*>
        merged = []
        for i in range(max(len(tpl.tokens), len(tokens))):
            a = tpl.tokens[i] if i < len(tpl.tokens) else '<*>'
            b = tokens[i] if i < len(tokens) else '<*>'
            if a == b:
                merged.append(a)
            else:
                merged.append('<*>')
        tpl.tokens = merged
        # 分隔符:取样本中多数(此处取首个样本的,异常时放宽为空白)
        if len(seps) >= len(tpl.seps):
            tpl.seps = seps[:len(tpl.tokens) - 1]

    # ---------- 学习 ----------

    def learn(self, lines: List[str]):
        """批量学习:逐行插入树"""
        for line in lines:
            if not line or not line.strip():
                continue
            tokens, seps = self.tokenize(line)
            if not tokens:
                continue
            keys = self._tree_path_keys(tokens)

            # 沿树下行
            node = self.root
            for k in keys:
                if k not in node:
                    node[k] = {}
                node = node[k]
            leaf = node.setdefault('__templates__', [])

            # 叶子内相似度匹配
            best, best_sim = None, 0.0
            for tpl in leaf:
                s = self._similarity(tokens, tpl.tokens)
                if s > best_sim:
                    best, best_sim = tpl, s

            if best and best_sim >= self.sim_threshold:
                self._merge(tokens, seps, best)
                if len(best.samples) < 50:
                    best.samples.append(line)
            else:
                tpl = Template(tokens=tokens, seps=seps, count=1, samples=[line])
                leaf.append(tpl)
                self.templates.append(tpl)

    # ---------- 正则生成 ----------

    def template_to_regex(self, tpl: Template, semantic_fields: Optional[Dict[int, str]] = None) -> Optional[str]:
        """
        把模板泛化为 Stage1 正则:
        ^<头部 token 序列(常量转义/变量类型化)>(?P<message>.+)$
        头部 = 前 max_prefix 个 token(合并时校验过的范围),避免过拟合;
        若头部全为变量,向后扩展到第一个常量。
        KV 格式特化:头部提前到第一个 KEY=" 之前,让 KV 对整体进入 message
        (否则 KV 键被划进头部,Stage2 无法从 message 提取)。
        """
        end = min(len(tpl.tokens), self.max_prefix)
        # 头部全变量时向后扩展到出现常量
        if all(is_var(t) for t in tpl.tokens[:end]):
            while end < len(tpl.tokens) and is_var(tpl.tokens[end]):
                end += 1
            end = min(end + 1, len(tpl.tokens))
        # 语义边界:语义标注的位置是"头部语义",message 应从最后一个语义字段后开始
        # (避免 message 开头内容如 kernel: DMA 的 DMA 被渲染进头部导致碎片)
        if semantic_fields:
            sem_positions = [p for p in semantic_fields if 0 <= p < end]
            if len(sem_positions) >= 2:
                end = min(len(tpl.tokens), max(sem_positions) + 1)
        # KV 格式特化:多数样本含 KEY=" 时,message 起点提前到第一个 KV 键
        if tpl.samples:
            kv_hits = sum(1 for s in tpl.samples[:20] if re.search(r'\w+="', s))
            if kv_hits / max(len(tpl.samples[:20]), 1) > 0.5:
                # 从原始样本的 token 找第一个 KV 键位置(模板中该位置可能已被合并为 <*>)
                s0_tokens = self.tokenize(tpl.samples[0])[0]
                for i, tok in enumerate(s0_tokens):
                    if re.match(r'^\w+="', tok):
                        if i < end:
                            end = i
                        break
        if end == 0:
            return r'^(?P<message>.+)$'

        parts = []
        used_fields: set = set()
        for i in range(end):
            tok = tpl.tokens[i]
            fname = (semantic_fields or {}).get(i)
            if is_var(tok) or force_var(tok):
                # 变量 token(含强制变量化:类型化/含数字):从首个样本推断类型
                sample_tok = None
                if tpl.samples and i < len(self.tokenize(tpl.samples[0])[0]):
                    sample_tok = self.tokenize(tpl.samples[0])[0][i]
                if fname and fname not in used_fields:
                    if fname == 'program':
                        # 变量 program(合并后 <*> 或多个值):必须泛化,
                        # 否则 named_group_regex 会用第一个样本值生成字面,
                        # 只匹配该值(如 Security-Auditing:),覆盖掉落到 95%+
                        parts.append(r'(?P<program>\S+)')
                    else:
                        from .stage1_semantics import named_group_regex
                        used_fields.add(fname)
                        parts.append(named_group_regex(fname, tok, sample_tok))
                else:
                    parts.append(var_type_regex(sample_tok or tok))
            else:
                # 常量位置:普通转义;若语义要求命名(如 program)则加命名组
                if fname == 'program' and fname not in used_fields:
                    used_fields.add(fname)
                    parts.append(f'(?P<program>{re.escape(tok)})')
                elif tok in _MONTHS:
                    # 有界枚举:月份 -> (?:Jan|Feb|...|Dec),跨月不失配
                    parts.append(_MONTH_RE)
                elif tok in _WEEKDAYS:
                    parts.append(_WEEKDAY_RE)
                elif _LEVEL_TOKEN_RE.fullmatch(tok):
                    # 有界枚举:日志级别 [notice]/[error] -> 枚举
                    parts.append(_LEVELS_RE)
                elif _BRACKET_WEEKDAY_RE.match(tok):
                    # 连写星期 token "[Sat" -> \[(?:Mon|...|Sun)
                    parts.append(r'\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)')
                else:
                    parts.append(re.escape(tok))
            if i < end - 1:
                sep = tpl.seps[i] if i < len(tpl.seps) else ' '
                parts.append(re.escape(sep))

        prefix = ''.join(parts)
        # 若头部已覆盖全部 token(整行固定),直接收尾;否则剩余部分收进 message
        if end >= len(tpl.tokens):
            return f'^{prefix}$'
        return f'^{prefix}(?P<message>.+)$'

    # ---------- 输出 ----------

    def _head_sig(self, tpl: Template, sem: Optional[Dict[int, str]], end: int) -> tuple:
        """
        头部结构签名(用于分组合并):
        - 变量/强制变量化 token -> 按样本真实 token 分类(与 template_to_regex 的
          var_type_regex 推断一致,避免模板 token 已被合并为 <*> 时 classify('<*>')=<OTHER>
          与常量分类不同,导致"同正则"的模板分到不同组产生冗余条目)
        - 语义标注字段位置 -> 按样本 token 分类
        - 枚举词(月份/星期/级别)-> 按枚举类型
        - 其他常量 -> 按具体值(保特异性:combo != other_host)
        """
        sample_toks = tpl.samples[0].split() if tpl.samples else []
        sig = []
        for i, t in enumerate(tpl.tokens[:end]):
            s = sample_toks[i] if i < len(sample_toks) else t
            if is_var(t) or force_var(t):
                sig.append(('V', classify_token(s)))
            elif sem and i in sem:
                sig.append(('S', classify_token(s)))
            elif t in _MONTHS or t in _WEEKDAYS or _LEVEL_TOKEN_RE.fullmatch(t) or _BRACKET_WEEKDAY_RE.match(t):
                sig.append(('E', 'enum'))
            else:
                sig.append(('C', t))
        return tuple(sig)

    @staticmethod
    def _merge_templates(tpls: List[Template]) -> Template:
        """组内模板逐位置泛化合并(count 累加,样本合并,seps 取 count 最大者)"""
        merged = Template(tokens=list(tpls[0].tokens), seps=list(tpls[0].seps), count=0, samples=[])
        for t in tpls:
            merged.count += t.count
            mt = []
            for i in range(max(len(merged.tokens), len(t.tokens))):
                a = merged.tokens[i] if i < len(merged.tokens) else '<*>'
                b = t.tokens[i] if i < len(t.tokens) else '<*>'
                mt.append(a if a == b else '<*>')
            merged.tokens = mt
            for s in t.samples:
                if len(merged.samples) < 50 and s not in merged.samples:
                    merged.samples.append(s)
        rep = max(tpls, key=lambda t: t.count)
        merged.seps = list(rep.seps)
        return merged

    def to_pattern_dicts(self, semantic_provider=None, min_count: int = 3) -> List[Dict]:
        """
        导出为 Stage1 YAML 的 pattern dict 列表。
        分组键 = 头部结构签名(语义字段/变量/枚举按类型,常量按值):
        "头部相同(message 区不同)"的模板合并为一个正则,大幅削减碎片。
        semantic_provider: 可选函数 tpl -> {位置: 字段名},用于生成命名组正则
        min_count: 过滤 count < 该值的模板组(噪声/异常行,如"注销成功"等碎片)
        """
        groups: Dict[tuple, List[Template]] = {}
        sems: Dict[tuple, Dict[int, str]] = {}
        for tpl in self.templates:
            sem = semantic_provider(tpl) if semantic_provider else None
            # 预演 end(与 template_to_regex 相同逻辑),用于签名范围
            end = min(len(tpl.tokens), self.max_prefix)
            if sem:
                sp = [p for p in sem if 0 <= p < end]
                if len(sp) >= 2:
                    end = min(len(tpl.tokens), max(sp) + 1)
            sig = self._head_sig(tpl, sem, end)
            groups.setdefault(sig, []).append(tpl)
            sems.setdefault(sig, sem)

        out = []
        for i, (sig, tpls) in enumerate(sorted(groups.items(), key=lambda kv: -sum(t.count for t in kv[1]))):
            merged = self._merge_templates(tpls)
            if merged.count < min_count:
                # 低 count 模板组:噪声/异常行,不导出(防过拟合,减少库碎片)
                continue
            sem = sems[sig]
            regex = self.template_to_regex(merged, sem)
            if not regex:
                continue
            extractor = 'generic'
            if merged.samples:
                kv_hits = sum(1 for s in merged.samples if re.search(r'\w+="', s))
                if kv_hits / len(merged.samples) > 0.5:
                    extractor = 'kv_parser'
            out.append({
                'name': f'fmt_{i:03d}',
                # priority:count 越大越优先(值越小),映射到 [1,100]
                # 避免所有模板同为 50 导致匹配排序失效;高频模板先匹配,碎片小模板靠后
                'priority': max(1, min(100, 100 - int(merged.count // 10))),
                'regex': regex,
                'extractor': extractor,
                'sample': (merged.samples[0] if merged.samples else '')[:2000],
                'sample_logs': merged.samples[:50],
                'count': merged.count,
            })

        # Bug 修复:签名(sig 用常量值)与正则生成(force_var 变量化)不一致,
        # 导致"不同模板组生成相同正则"。按 regex 去重,保证产出唯一正则
        # (相同 regex 的组语义等价,合并 count)。
        seen_regex = {}
        for p in out:
            r = p['regex']
            if r in seen_regex:
                seen_regex[r]['count'] += p['count']
            else:
                seen_regex[r] = p
        out = list(seen_regex.values())
        for _i, p in enumerate(out):
            p['name'] = f'fmt_{_i:03d}'
        return out


def learn_from_file(filepath: str, max_lines: Optional[int] = None) -> DrainLearner:
    """从文件学习(流式读取,可限制行数)"""
    learner = DrainLearner()
    n = 0
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            if max_lines and n >= max_lines:
                break
            line = line.strip()
            if not line:
                continue
            learner.learn([line])
            n += 1
    return learner
