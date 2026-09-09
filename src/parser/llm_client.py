#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLM 客户端 - 调用 OpenAI 兼容 API
"""
import json
import re
import time
from typing import List, Dict, Optional

from ..config.settings import get_config
from ..utils.logger import setup_logger

logger = setup_logger("llm_client")


class LLMClient:
    """LLM 客户端"""

    def __init__(self):
        self.config = get_config()
        self._client = None
        self._last_call_time = 0

    def _get_client(self):
        """延迟初始化 OpenAI 客户端（带超时）"""
        if self._client is None:
            try:
                from openai import OpenAI
                self._client = OpenAI(
                    base_url=self.config.llm_base_url,
                    api_key=self.config.llm_api_key,
                    timeout=self.config.llm_timeout,  # 超时秒数，防止LLM API无响应
                )
            except ImportError:
                logger.error("openai 包未安装，请运行: pip install openai")
                raise
        return self._client

    def _respect_cooldown(self):
        """遵守冷却时间"""
        cooldown = self.config.llm_annotation_cooldown
        elapsed = time.time() - self._last_call_time
        if elapsed < cooldown and self._last_call_time > 0:
            wait = cooldown - elapsed
            logger.info(f"LLM 冷却中，等待 {wait:.0f}s")
            time.sleep(wait)

    def call_json(self, prompt: str, system_prompt: str = None, max_retries: int = 3) -> Optional[Dict]:
        """
        通用 LLM 调用，返回解析后的 JSON（带重试）

        Args:
            prompt: 用户提示
            system_prompt: 系统提示（可选）
            max_retries: 最大重试次数

        Returns:
            解析后的 dict，或 None
        """
        if not self.config.llm_enabled:
            logger.info("LLM 已禁用")
            return None

        if system_prompt is None:
            system_prompt = (
                "你是日志分析专家。你的每次回答必须且只能是一个合法的 JSON 对象"
                "（不要 markdown 代码块、不要解释文字、不要分析过程、不要列表编号）。"
                "任何非 JSON 内容的回答都视为失败。"
            )

        for attempt in range(1, max_retries + 1):
            self._respect_cooldown()

            try:
                client = self._get_client()
                logger.info(f"LLM Prompt:\n{prompt[:2000]}")
                kwargs = dict(
                    model=self.config.llm_model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=self.config.llm_temperature,
                    max_tokens=self.config.llm_max_tokens,
                )
                # 服务端强制 JSON 输出(OpenAI 兼容接口均支持),避免模型返回解释文字导致解析失败
                try:
                    kwargs["response_format"] = {"type": "json_object"}
                except Exception:
                    pass
                response = client.chat.completions.create(**kwargs)
                self._last_call_time = time.time()

                content = (response.choices[0].message.content or "").strip()
                if not content:
                    # 服务端返回空响应(限流/异常):不抛 AttributeError,按失败重试
                    raise ValueError("LLM 返回空内容(可能被服务端限流)")
                logger.info(f"LLM Response:\n{content[:2000]}")
                result = self._parse_json_response(content)
                if result is not None:
                    return result
                logger.warning(f"LLM 返回解析失败（尝试 {attempt}/{max_retries}）")

            except Exception as e:
                logger.warning(f"LLM 调用失败（尝试 {attempt}/{max_retries}）: {e}")

            if attempt < max_retries:
                wait = 5 * attempt
                logger.info(f"  等待 {wait}s 后重试...")
                time.sleep(wait)

        logger.error(f"LLM 调用最终失败（已重试 {max_retries} 次）")
        return None

    def _parse_json_response(self, content: str) -> Optional[Dict]:
        """解析 LLM 返回的 JSON（支持去除 markdown 标记与模型思维链）"""
        content = content.strip()

        # 剥离模型思维链(<think>...</think>),只保留答案部分
        content = re.sub(r"<think>.*?</think>", "", content, flags=re.S).strip()

        # 去除可能的 markdown 代码块
        if content.startswith("```"):
            lines = content.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            content = "\n".join(lines).strip()

        try:
            result = json.loads(content)
            if isinstance(result, dict):
                return result
            if isinstance(result, list):
                # LLM 未按格式返回(逐条标注数组):包装标记,调用方取不到期望键即放弃,
                # 不触发重试(重试大概率仍返回数组,只会浪费时间)
                logger.warning(f"LLM 返回数组(未按格式),放弃该次标注: 数组长度 {len(result)}")
                return {"_format_list": result}
            logger.warning(f"LLM 返回不是 dict: {type(result)}")
            return None
        except json.JSONDecodeError:
            # 兜底:模型夹带解释文字时,提取内容中第一个 { 到最后一个 } 的 JSON 子串
            s = content.find("{")
            e = content.rfind("}")
            if 0 <= s < e:
                try:
                    result = json.loads(content[s:e + 1])
                    if isinstance(result, dict):
                        logger.warning("LLM 返回含解释文字,已提取 JSON 子串解析成功")
                        return result
                except json.JSONDecodeError:
                    pass
            logger.error(f"LLM 返回 JSON 解析失败(含子串提取): {content[:200]}")
            logger.debug(f"原始返回: {content[:500]}")
            return None

    # ==================== 兼容旧接口 ====================

    def generate_regex(self, samples: List[str]) -> Optional[Dict]:
        """旧接口：直接生成正则（兼容）"""
        prompt = self._build_regex_prompt(samples)
        result = self.call_json(prompt)
        if result and self._validate_regex(result.get("regex", ""), samples):
            return result
        return None

    def _build_regex_prompt(self, samples: List[str]) -> str:
        """构造正则生成 prompt"""
        samples_text = "\n".join(f"{i+1}. {s}" for i, s in enumerate(samples))
        return f"""以下是 {len(samples)} 条同一格式的 syslog 日志样本：

{samples_text}

请生成一个 Python 正则表达式。返回纯 JSON:
{{"name": "格式名", "description": "描述", "regex": "正则表达式", "extractor": "generic", "priority": 50}}

要求: 使用命名捕获组 (?P<name>...)，正则必须匹配所有样本。只返回纯 JSON。"""

    def _validate_regex(self, regex: str, samples: List[str]) -> bool:
        """验证正则能匹配所有样本"""
        try:
            compiled = re.compile(regex)
        except re.error as e:
            logger.warning(f"正则编译失败: {e}")
            return False

        for sample in samples:
            if not compiled.match(sample):
                logger.warning(f"正则无法匹配样本: {sample[:100]}...")
                return False
        return True
