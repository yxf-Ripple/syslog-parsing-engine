"""
正则模式加载器 - 从 YAML 加载、编译、匹配、追加模式
"""
import re
import os
import yaml
import time
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Any

from ..config.settings import get_config
from ..utils.logger import setup_logger

logger = setup_logger("pattern_loader")


@dataclass
class Pattern:
    """单个解析模式"""
    name: str
    description: str
    priority: int
    regex: str
    extractor: str
    format: str = ""  # 格式类别(对齐 example 旧解析器 log_format 类型,如 rfc5424_json)
    sample: str = ""
    sample_logs: list = field(default_factory=list)  # 用于改进的样本日志
    compiled_regex: re.Pattern = field(default=None, repr=False)

    def compile(self):
        """预编译正则"""
        if self.compiled_regex is None:
            self.compiled_regex = re.compile(self.regex)


class PatternLoader:
    """正则模式加载器"""

    def __init__(self, patterns_path: str = None):
        config = get_config()
        self.patterns_path = Path(patterns_path or config.stage1_patterns_path)
        self.patterns: List[Pattern] = []
        self._load()

    def _load(self):
        """从 YAML 加载并预编译所有模式"""
        if not self.patterns_path.exists():
            logger.warning(f"模式文件不存在: {self.patterns_path}，使用空模式库")
            return

        with open(self.patterns_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        raw_patterns = data.get("patterns") or []
        self.patterns = []
        for p in raw_patterns:
            try:
                pattern = Pattern(
                    name=p["name"],
                    description=p.get("description", ""),
                    priority=p.get("priority", 999),
                    regex=p["regex"],
                    extractor=p.get("extractor", "generic"),
                    format=p.get("format", ""),
                    sample=p.get("sample", ""),
                )
                pattern.compile()
                self.patterns.append(pattern)
            except KeyError as e:
                logger.error(f"模式定义缺少字段 {e}: {p.get('name', '?')}")
            except re.error as e:
                logger.error(f"正则编译失败 [{p.get('name', '?')}]: {e}")

        # 按 priority 升序排列
        self.patterns.sort(key=lambda p: p.priority)
        logger.info(f"已加载 {len(self.patterns)} 个正则模式")

    def match(self, line: str) -> Optional[Tuple[str, re.Match, str, str]]:
        """
        尝试匹配一行日志

        Returns:
            (pattern_name, match_obj, extractor_type, format) 或 None
            (format 对齐 example log_format 类型,可能为空字符串)
        """
        for pattern in self.patterns:
            m = pattern.compiled_regex.match(line)
            if m:
                return (pattern.name, m, pattern.extractor, pattern.format)
        return None

    def add_pattern(self, pattern_dict: Dict[str, str]) -> bool:
        """
        动态添加新模式（内存 + 持久化到 YAML）

        Args:
            pattern_dict: {name, description, regex, extractor, priority?, sample?, sample_logs?}

        Returns:
            是否成功
        """
        try:
            # 验证正则合法性
            test_regex = re.compile(pattern_dict["regex"])
        except re.error as e:
            logger.error(f"新模式正则编译失败: {e}")
            return False

        # 创建 Pattern 对象
        new_sample_logs = pattern_dict.get("sample_logs", [])
        pattern = Pattern(
            name=pattern_dict["name"],
            description=pattern_dict.get("description", ""),
            priority=int(pattern_dict.get("priority", 999)),
            regex=pattern_dict["regex"],
            extractor=pattern_dict.get("extractor", "generic"),
            sample=pattern_dict.get("sample", ""),
            sample_logs=new_sample_logs,
        )
        pattern.compile()

        # 检查是否已存在同名模式
        for i, existing in enumerate(self.patterns):
            if existing.name == pattern.name:
                # 更新已有模式：合并样本日志
                if not pattern.sample_logs:
                    pattern.sample_logs = existing.sample_logs
                merged_logs = existing.sample_logs + new_sample_logs
                # 去重并限制数量（最多保留 500 条）
                pattern.sample_logs = list(dict.fromkeys(merged_logs))[:500]
                self.patterns[i] = pattern
                logger.info(f"更新已有模式: {pattern.name} (样本数: {len(pattern.sample_logs)})")
                break
        else:
            # 添加新模式
            self.patterns.append(pattern)
            logger.info(f"添加新模式: {pattern.name} (样本数: {len(pattern.sample_logs)})")

        # 重新排序
        self.patterns.sort(key=lambda p: p.priority)

        # 持久化
        self._save()
        return True

    def _save(self):
        """将当前模式保存回 YAML（安全写入：先写临时文件再替换）"""
        data = {
            "patterns": [
                {
                    "name": p.name,
                    "priority": p.priority,
                    "regex": p.regex,
                    "extractor": p.extractor,
                    "format": p.format,
                    "sample": p.sample,
                }
                for p in self.patterns
            ],
            "metadata": {
                "version": "1.0",
                "last_updated": time.strftime("%Y-%m-%d"),
                "llm_fallback_enabled": True,
            },
        }

        # 安全写入：先写临时文件，成功后再原子替换
        tmp_path = str(self.patterns_path) + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        os.replace(tmp_path, self.patterns_path)

    @property
    def count(self) -> int:
        return len(self.patterns)
