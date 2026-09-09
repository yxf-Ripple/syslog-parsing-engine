# -*- coding: utf-8 -*-
"""
重建 Stage2 规则,type 对齐最终 stage1_patterns.yaml 的 name。
- 按正则匹配的日志文件分组(同格式),组内 LLM 标注结果复用(控制 LLM 调用)
- 文件列表由 learn_files.py 传入(本次学习的文件);文件不存在时容错跳过
"""
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.parser.pattern_loader import PatternLoader

STAGE1 = ROOT / "stage1_patterns.yaml"
STAGE2 = ROOT / "stage2_patterns.yaml"

# 默认文件列表(learn_files 未传 source_files 时的兜底;文件不存在会自动跳过)
FILE_PATHS = {
    'tianrongxin_kv': ROOT / "testdata" / "udp_syslog.log",
    'rfc5424': ROOT / "testdata" / "安管平台1#<host>#2025-06-19-001.log",
    'bsd_windows': ROOT / "testdata" / "3机组历史数据站1#<host>#2025-06-19-001.log",
}


def group_key(regex: str, file_paths: dict) -> str:
    """按实际匹配的文件分组(最可靠:测试正则能匹配哪个文件的样本)"""
    for tag, path in file_paths.items():
        c = re.compile(regex)
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for _ in range(300):
                    line = f.readline().strip()
                    if line and c.match(line):
                        return tag
        except OSError:
            continue  # 文件不存在/被删:跳过该文件
    return 'unknown'


def extract_messages(pattern, paths, n=6):
    """用 pattern 的正则在候选文件中提取 message 样本(任一文件命中即可)"""
    c = re.compile(pattern.regex)
    if 'message' not in c.groupindex:
        return []  # 整行固定模板无 message 组
    msgs = []
    for path in paths:
        try:
            f = open(path, encoding="utf-8", errors="replace")
        except OSError:
            continue  # 文件不存在/被删:跳过
        with f:
            for line in f:
                line = line.strip()
                m = c.match(line)
                if m and len(msgs) < n:
                    msgs.append(m.group('message'))
                if len(msgs) >= n:
                    return msgs
    return msgs


def run(stage1_path=None, stage2_path=None, no_llm: bool = False, source_files=None,
        merge_existing: bool = False, forwarded: bool = False) -> int:
    """
    重建 Stage2 规则,type 对齐 stage1 的 name。
    供 CLI(main)与 learn_files.py 批量学习后自动调用。

    Args:
        stage1_path: Stage1 YAML 路径(默认项目根 stage1_patterns.yaml)
        stage2_path: Stage2 YAML 输出路径(默认项目根 stage2_patterns.yaml)
        no_llm: 为 True 时跳过 LLM 标注(无预置规则,产出空规则)
        source_files: 本次学习的日志文件列表(learn_files 传入,用于按文件分组提取样本)
        merge_existing: 为 True 时与现有 stage2 规则合并(按 field/type/format 去重,新覆盖旧),
                        避免自动触发学习(只传新格式文件)时丢失已学格式的规则
        forwarded: 是否转发 syslog(由自动学习时 LLM 检查模板得出,透传给字段标注)
    Returns:
        规则总数
    """
    from src.parser.llm_annotator import annotate_and_build_stage2

    stage1_path = Path(stage1_path) if stage1_path else STAGE1
    stage2_path = Path(stage2_path) if stage2_path else STAGE2

    # 文件列表:优先用调用方传入的(本次学习的文件),否则用默认兜底
    if source_files:
        file_paths = {}
        for i, p in enumerate(source_files):
            file_paths[f"src{i}"] = Path(p)
    else:
        file_paths = dict(FILE_PATHS)

    loader = PatternLoader(str(stage1_path))

    # 按文件分组(每个文件独立标注,format=文件标签)。
    # 修复:同一 stage1 正则可匹配多个文件(如 ag 与工控共用 fmt_003),
    # 旧逻辑按"正则匹配的第一个文件"分组会把它们混在一起,导致规则错位。
    def _matches_file(regex: str, path: Path) -> bool:
        c = re.compile(regex)
        try:
            f = open(path, encoding="utf-8", errors="replace")
        except OSError:
            return False
        with f:
            for _ in range(300):
                line = f.readline().strip()
                if line and c.match(line):
                    return True
        return False

    groups = {}  # 文件标签 -> {"pats": [匹配的 pattern], "path": 文件路径}
    for g, path in file_paths.items():
        matched = [p for p in loader.patterns if _matches_file(p.regex, path)]
        if matched:
            groups[g] = {"pats": matched, "path": path}

    all_rules = []
    stats = {}
    llm_groups = 0

    for g, info in groups.items():
        paths = [info["path"]]
        # 收集该文件所有匹配 pattern 的 message 样本(每文件一次标注,组内规则复用)
        all_msgs = []
        for p in info["pats"][:20]:
            all_msgs.extend(extract_messages(p, paths))
        if not all_msgs:
            continue
        if no_llm:
            rules = []
        else:
            rules = annotate_and_build_stage2(g, all_msgs, forwarded=forwarded)
            if rules:
                llm_groups += 1
        # type 对齐 stage1 name:同文件格式的规则适用于该文件匹配的每个 pattern
        # format 保留来源文件(修复多文件共用同一 stage1 正则时规则错位)
        g_rules = []
        for p in info["pats"]:
            for r in rules:
                rr = dict(r)
                rr['type'] = p.name
                rr['format'] = g
                g_rules.append(rr)
        all_rules.extend(g_rules)
        stats[g] = {"patterns": len(info["pats"]), "rules": len(g_rules)}
        print(f"[{g}] {len(info['pats'])} 个模式 -> {len(g_rules)} 条规则")

    # 写 stage2(整体重建;merge_existing 时先合并现有规则)
    import yaml
    if merge_existing and Path(stage2_path).exists():
        try:
            with open(stage2_path, encoding="utf-8") as f:
                existing = (yaml.safe_load(f) or {}).get("patterns", []) or []
        except Exception:
            existing = []
        if existing:
            def _key(r):
                return (r.get("field_name"), r.get("type"), r.get("format"))
            new_keys = {_key(r) for r in all_rules}
            all_rules = [r for r in existing if _key(r) not in new_keys] + all_rules
    data = {
        "patterns": all_rules,
        "metadata": {"version": "2.1", "last_updated": time.strftime("%Y-%m-%d"),
                     "note": "type 对齐 stage1 最终 name;字段语义完全来自 LLM 标注(无预置规则)"},
    }
    tmp = str(stage2_path) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    import os
    os.replace(tmp, str(stage2_path))
    print(f"已重建 {stage2_path}: 共 {len(all_rules)} 条规则")
    print("LLM 标注组数:", llm_groups)
    return len(all_rules)


def main():
    run()


if __name__ == "__main__":
    main()
