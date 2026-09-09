#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Syslog Parser CLI 入口
流式逐行处理，输出 JSON Lines 格式

用法:
    python -m src.main --input testdata/udp_syslog.log --output result/udp.jsonl
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

# 确保项目根目录在 sys.path 中
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.parser.pattern_loader import PatternLoader
from src.parser.field_extractor import extract
from src.parser.schema import to_standardized_event
from src.parser.nested import attach_nested
from src.config.settings import get_config
from src.utils.logger import setup_logger

logger = setup_logger("main")


def parse_file_sync(
    input_path: str,
    output_path: str,
    error_path: str = None,
    patterns_path: str = None,
    progress_interval: int = 10000,
    output_format: str = "jsonl",
    nested: bool = False,
):
    """
    纯正则解析（无 LLM）

    Args:
        output_format: "json" (JSON 数组) 或 "jsonl" (每行一个 JSON)
        nested: 开启嵌套 syslog 剥壳(附加到 structured_data.nested_syslog,不改现有字段)
    """
    config = get_config()
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    loader = PatternLoader(patterns_path)
    logger.info(f"纯正则模式: 已加载 {loader.count} 个正则模式")

    stats = {"total": 0, "matched": 0, "unmatched": 0, "start_time": time.time()}
    results = []

    with open(input_path, "r", encoding="utf-8", errors="replace") as fin:
        error_file = None
        if error_path:
            os.makedirs(os.path.dirname(error_path) or ".", exist_ok=True)
            error_file = open(error_path, "w", encoding="utf-8")

        try:
            for line_no, line in enumerate(fin, 1):
                line = line.rstrip("\n\r")
                if not line:
                    continue

                stats["total"] += 1
                match_result = loader.match(line)

                if match_result:
                    pattern_name, match_obj, extractor_type, pattern_format = match_result
                    result = extract(match_obj, extractor_type, line, pattern_name=pattern_name,
                                     pattern_format=pattern_format)
                    result["_pattern_name"] = pattern_name
                    result["_line_no"] = line_no
                    # 输出对齐 StandardizedEvent 字段形状(内部字段保留在 parsed_content)
                    result = to_standardized_event(result)
                    if nested:
                        # 附加功能:嵌套 syslog 剥壳(仅追加,不影响现有字段)
                        result = attach_nested(result.get("parsed_content") or {}, loader, result)
                    results.append(result)
                    stats["matched"] += 1
                else:
                    stats["unmatched"] += 1
                    if error_file:
                        error_entry = {
                            "_meta": {"reason": "no_pattern_matched", "line_no": line_no},
                            "raw": line,
                        }
                        error_file.write(json.dumps(error_entry, ensure_ascii=False) + "\n")

                if line_no % progress_interval == 0:
                    elapsed = time.time() - stats["start_time"]
                    rate = stats["total"] / elapsed if elapsed > 0 else 0
                    logger.info(
                        f"进度: {stats['total']} 行 | "
                        f"命中: {stats['matched']} | "
                        f"未命中: {stats['unmatched']} | "
                        f"速率: {rate:.0f} 行/秒"
                    )
        finally:
            if error_file:
                error_file.close()

    # 写入输出文件
    with open(output_path, "w", encoding="utf-8") as fout:
        if output_format == "json":
            json.dump(results, fout, ensure_ascii=False, default=str, indent=2)
        else:
            for result in results:
                fout.write(json.dumps(result, ensure_ascii=False, default=str) + "\n")

    elapsed = time.time() - stats["start_time"]
    rate = stats["total"] / elapsed if elapsed > 0 else 0
    logger.info("=" * 60)
    logger.info(f"[DONE] 转化完成: {input_path}")
    logger.info(f"总行数: {stats['total']}")
    logger.info(f"成功匹配: {stats['matched']}")
    logger.info(f"未匹配: {stats['unmatched']}")
    logger.info(f"耗时: {elapsed:.2f}s")
    logger.info(f"平均速率: {rate:.0f} 行/秒")
    logger.info(f"输出文件: {output_path}")
    logger.info("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Syslog 解析引擎",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 纯正则模式（最快）
  python -m src.main -i testdata/udp_syslog.log -o result/udp.jsonl

  # 指定错误输出
  python -m src.main -i testdata/udp_syslog.log -o result/udp.jsonl -e result/udp_error.jsonl
        """,
    )

    parser.add_argument("--input", "-i", required=True, help="输入日志文件路径")
    parser.add_argument("--output", "-o", required=True, help="输出 JSONL 文件路径")
    parser.add_argument("--error", "-e", default=None, help="解析失败的日志输出路径")
    parser.add_argument("--patterns", "-p", default=None, help="自定义正则模式 YAML 文件路径")
    parser.add_argument("--progress", type=int, default=10000, help="进度打印间隔（行数，默认 10000）")
    parser.add_argument("--nested", action="store_true", help="启用嵌套 syslog 剥壳(附加到 structured_data.nested_syslog)")

    args = parser.parse_args()

    if not os.path.exists(args.input):
        logger.error(f"输入文件不存在: {args.input}")
        sys.exit(1)

    parse_file_sync(
        input_path=args.input,
        output_path=args.output,
        error_path=args.error,
        patterns_path=args.patterns,
        progress_interval=args.progress,
        nested=args.nested,
    )


if __name__ == "__main__":
    main()
