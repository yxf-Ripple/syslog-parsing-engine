#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
批量离线学习 Stage1 正则(任意多个日志文件)
------------------------------------------
对每个文件:标准 Drain 聚类 → force_var 泛化 → 预置表/LLM 语义标注 →
命名组正则 → 增量合并进 stage1_patterns.yaml(按 regex 去重)。

用法:
    python scripts/learn_files.py a.log b.log c.log d.log e.log
    python scripts/learn_files.py --dir testdata/新设备      # 学习目录下所有 *.log
    python scripts/learn_files.py f.log --max-lines 50000    # 限制每个文件学习行数
    python scripts/learn_files.py f.log --output tmp/test.yaml  # 输出到独立文件(隔离)

学习后:
    python scripts/rebuild_stage2.py   # 生成/对齐 Stage2 字段规则
    然后在线转化直接生效(模式库 stage1_patterns.yaml 已更新)。
"""
import argparse
import glob
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.parser.drain_learner import learn_from_file
from src.parser.stage1_semantics import template_semantics
from src.offline_drain import merge_into_yaml


def main():
    ap = argparse.ArgumentParser(description="批量离线学习 Stage1 正则")
    ap.add_argument("inputs", nargs="*", help="日志文件路径(可多个)")
    ap.add_argument("--dir", default=None, help="学习目录下所有 *.log")
    ap.add_argument("--max-lines", type=int, default=None, help="每个文件最多学习行数(默认全量)")
    ap.add_argument("--output", "-o", default=str(ROOT / "stage1_patterns.yaml"), help="Stage1 YAML 输出路径")
    ap.add_argument("--stage2", default=str(ROOT / "stage2_patterns.yaml"), help="Stage2 YAML 输出路径")
    ap.add_argument("--no-llm", action="store_true", help="禁用 LLM 语义标注(仅匿名正则/预置规则)")
    args = ap.parse_args()

    files = list(args.inputs)
    if args.dir:
        files += sorted(glob.glob(os.path.join(args.dir, "*.log")))
    if not files:
        print("未指定输入文件。用法: python scripts/learn_files.py a.log b.log ... 或 --dir <目录>")
        sys.exit(1)

    # 禁用 LLM 时用空语义(预置表仍生效,LLM 不调用)
    provider = None if args.no_llm else template_semantics

    t0 = time.time()
    for f in files:
        if not os.path.exists(f):
            print(f"跳过(文件不存在): {f}")
            continue
        s = time.time()
        try:
            lr = learn_from_file(f, max_lines=args.max_lines)
        except Exception as e:
            print(f"[{os.path.basename(f)}] 学习失败: {e}")
            continue
        pats = lr.to_pattern_dicts(semantic_provider=provider)
        total = merge_into_yaml(pats, args.output)
        print(f"[{os.path.basename(f)}] 模板 {len(lr.templates)} -> 正则 {len(pats)} | "
              f"合并后共 {total} 条 | {time.time()-s:.1f}s")
    print(f"\n总耗时 {time.time()-t0:.1f}s | 模式库: {args.output}")

    # 自动生成/对齐 Stage2(一次性完成两件事,框架仍分开存储)
    print("\n=== 自动生成 Stage2 字段规则 ===")
    try:
        from scripts.rebuild_stage2 import run as run_stage2
    except ImportError:
        # scripts 非包时按路径导入
        import importlib.util
        spec = importlib.util.spec_from_file_location("rebuild_stage2", ROOT / "scripts" / "rebuild_stage2.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        run_stage2 = mod.run
    n_rules = run_stage2(args.output, args.stage2, no_llm=args.no_llm, source_files=files)
    print(f"完成: Stage1({args.output}) + Stage2({args.stage2}, {n_rules} 条规则)")
    print("在线转化直接生效: python -m src.main --input <日志> --output out.jsonl")


if __name__ == "__main__":
    main()
