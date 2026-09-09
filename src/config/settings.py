"""
配置管理 - 从 .env 加载 LLM 和其他配置
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# 加载 .env 文件（位于项目根目录）
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
load_dotenv(PROJECT_ROOT / ".env")


class Config:
    """全局配置单例"""

    # LLM 配置
    llm_enabled: bool = os.getenv("LLM_ENABLED", "true").lower() == "true"
    llm_provider: str = os.getenv("LLM_PROVIDER", "openai_compatible")
    llm_base_url: str = os.getenv("LLM_BASE_URL", "http://<llm-gateway-host>:9901/v1")
    llm_api_key: str = os.getenv("LLM_API_KEY", "")
    llm_model: str = os.getenv("LLM_MODEL", "qwen3")
    llm_temperature: float = float(os.getenv("LLM_TEMPERATURE", "0.1"))
    llm_max_tokens: int = int(os.getenv("LLM_MAX_TOKENS", "4096"))
    llm_timeout: float = float(os.getenv("LLM_TIMEOUT", "120"))

    # LLM 触发阈值
    llm_trigger_sample_count: int = int(os.getenv("LLM_TRIGGER_SAMPLE_COUNT", "5"))
    llm_trigger_time_minutes: int = int(os.getenv("LLM_TRIGGER_TIME_MINUTES", "0"))
    llm_annotation_cooldown: int = int(os.getenv("LLM_ANNOTATION_COOLDOWN", "5"))
    # 自动离线学习开关:打开时,在线接收未匹配样本累积到阈值后自动触发离线学习(学模板+LLM 标注)
    llm_trigger_enabled: bool = os.getenv("LLM_TRIGGER_ENABLED", "false").lower() == "true"
    # 空闲触发:未匹配停止增长多少秒后也触发学习(让低于阈值的小样本格式也能学出来,如工控 12 条)
    llm_trigger_idle_seconds: float = float(os.getenv("LLM_TRIGGER_IDLE_SECONDS", "3"))

    # 引擎配置
    unmatched_batch_size: int = 50       # 积累多少条未命中后触发 LLM
    llm_sample_size: int = 50            # 送分类 LLM 的采样数
    max_concurrent_types: int = 3        # 同时处理的类型数

    # 离线流程配置
    offline_sample_size: int = 200       # 离线采样数量
    validation_threshold: float = 0.98   # 正则验证覆盖率阈值
    max_retry_count: int = 3             # LLM 调用最大重试次数

    # 路径配置
    stage1_patterns_path: str = str(PROJECT_ROOT / "stage1_patterns.yaml")
    stage2_patterns_path: str = str(PROJECT_ROOT / "stage2_patterns.yaml")
    output_dir: str = str(PROJECT_ROOT / "result")


_config = None


def get_config() -> Config:
    """获取配置单例"""
    global _config
    if _config is None:
        _config = Config()
    return _config
