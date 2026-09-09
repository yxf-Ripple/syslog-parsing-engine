#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
离线 Drain 模板学习 CLI
------------------------
用标准前缀树 Drain 从日志文件聚类出模板,确定性泛化为 Stage1 正则,
写入 stage1_patterns.yaml(增量合并,按正则去重)。

用法:
    python -m src.offline_drain -i testdata/udp_syslog.log [-o stage1_patterns.yaml] [--max-lines 50000]
"""
import argparse
import os
import re
import sys
import time
import yaml
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.parser.drain_learner import learn_from_file
from src.utils.logger import setup_logger

logger = setup_logger("offline_drain")


def merge_into_yaml(new_patterns: list, output_path: str):
    """增量写入 stage1 YAML:按正则去重合并;name/format 稳定(已存在保留,新 regex 按格式类别分配)。

    - 每个 pattern 带 format 字段(对齐 example 旧解析器 log_format 类型,按 sample 检测);
    - 命名规则(格式类别+稳定序号):已存在 regex 保留原 name/format,不再按 count 重排;
      新 regex 用 detect_format_category 定类别,在类别内取下一个空闲序号命名 <类别>_<NNN>。
    """
    from src.parser.stage1_semantics import detect_format_category

    existing = []
    if os.path.exists(output_path):
        with open(output_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        existing = data.get("patterns") or []

    existing_regexes = {p["regex"] for p in existing}
    by_regex = {}
    for p in existing:
        by_regex[p["regex"]] = p
    for p in new_patterns:
        if p["regex"] in by_regex:
            old = by_regex[p["regex"]]
            old["count"] = old.get("count", 0) + p.get("count", 0)
        else:
            by_regex[p["regex"]] = p

    patterns = sorted(by_regex.values(), key=lambda p: -p.get("count", 0))

    # 类别 -> 已占用最大序号(用于新 regex 分配稳定序号)
    cat_max: Dict[str, int] = {}
    for p in patterns:
        if p["regex"] in existing_regexes:
            # 已有:保留 name;format 缺失时按 sample 补(迁移旧库)
            if not p.get("format"):
                p["format"] = detect_format_category(p.get("sample", "") or "")
            m = re.match(r'^(?P<cat>.+)_(?P<idx>\d+)$', p.get("name", "") or "")
            if m:
                cat_max[m.group("cat")] = max(cat_max.get(m.group("cat"), -1), int(m.group("idx")))
        else:
            # 新 regex:按格式类别分配稳定序号
            fmt = detect_format_category(p.get("sample", "") or "")
            idx = cat_max.get(fmt, -1) + 1
            cat_max[fmt] = idx
            p["format"] = fmt
            p["name"] = f"{fmt}_{idx:03d}"

    yaml_data = {
        "patterns": [
            {k: v for k, v in p.items() if k in ("name", "format", "priority", "regex", "extractor", "sample", "count")}
            for p in patterns
        ],
        "metadata": {
            "version": "1.1",
            "last_updated": time.strftime("%Y-%m-%d"),
            "method": "standard_drain",
            "llm_fallback_enabled": False,
        },
    }
    tmp_path = output_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        yaml.dump(yaml_data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    os.replace(tmp_path, output_path)
    return len(patterns)


def main():
    parser = argparse.ArgumentParser(description="离线 Drain 模板学习")
    parser.add_argument("--input", "-i", required=True, help="输入日志文件")
    parser.add_argument("--output", "-o", default=str(PROJECT_ROOT / "stage1_patterns.yaml"))
    parser.add_argument("--max-lines", type=int, default=None, help="最多学习行数(默认全量)")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        logger.error(f"输入文件不存在: {args.input}")
        sys.exit(1)

    t0 = time.time()
    logger.info(f"[离线Drain] 学习: {args.input}")
    learner = learn_from_file(args.input, max_lines=args.max_lines)
    patterns = learner.to_pattern_dicts()
    logger.info(f"  模板 {len(learner.templates)} 个,合并后正则 {len(patterns)} 条,学习耗时 {time.time()-t0:.1f}s")

    total = merge_into_yaml(patterns, args.output)
    logger.info(f"  已写入 {args.output} (共 {total} 条模式)")
    for p in patterns[:5]:
        logger.info(f"    [{p['name']}] count={p['count']} {p['extractor']}: {p['regex'][:90]}")


if __name__ == "__main__":
    main()
