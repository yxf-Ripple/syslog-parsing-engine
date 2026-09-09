"""
日志配置 - 强制实时输出（无缓冲）
"""
import logging
import sys
import io

# 强制 stdout 无缓冲（关键：让 print/logging 立即可见）
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True)
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True)


def setup_logger(name: str = "syslog_parser", level: int = logging.INFO) -> logging.Logger:
    """创建并配置 logger（实时输出到控制台）"""
    logger = logging.getLogger(name)

    if not logger.handlers:
        logger.setLevel(level)

        # 控制台 handler（强制 flush）
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S"
        )
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # 避免重复日志
        logger.propagate = False

    return logger


def print_progress(message: str):
    """实时打印进度（强制刷新）"""
    print(f"[{__import__('time').strftime('%H:%M:%S')}] {message}", flush=True)
