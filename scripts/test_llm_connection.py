#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试 engine 的 LLM 配置(.env + settings)与网关连通性
----------------------------------------------------
用法:
    python scripts/test_llm_connection.py

检查项:
    1. 配置能否正常加载(优先复用 engine/src/config/settings.py 的真实加载路径,
       失败时回退为手工解析 engine/.env,以便继续测连接)
    2. 关键配置是否齐全(base_url / model / key)
    3. GET  {base_url}/models             —— 网关可达性 + 配置的模型是否存在
    4. POST {base_url}/chat/completions   —— 用配置的 model/temperature/max_tokens
       发一次真实对话,并带 response_format=json_object(引擎 LLM 标注依赖此模式)

退出码: 0 = 全部通过, 1 = 存在失败项
"""
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


# ==================== 1. 配置加载 ====================

def _manual_env() -> dict:
    """手工解析 engine/.env 的 KEY=VALUE 行(settings.py 加载失败时的兜底)"""
    raw = {}
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            raw[k.strip()] = v.strip().strip('"').strip("'")
    return raw


def load_config():
    """返回 (字段字典, 来源说明, 是否手工解析)。统一字段为小写 llm_*。"""
    try:
        from src.config.settings import get_config
        cfg = get_config()
        d = {
            "llm_enabled": bool(cfg.llm_enabled),
            "llm_base_url": cfg.llm_base_url,
            "llm_api_key": cfg.llm_api_key,
            "llm_model": cfg.llm_model,
            "llm_temperature": float(cfg.llm_temperature),
            "llm_max_tokens": int(cfg.llm_max_tokens),
            "llm_timeout": float(cfg.llm_timeout),
        }
        return d, "engine/src/config/settings.py (真实加载路径)", False
    except Exception as e:
        raw = _manual_env()
        src = "手工解析 .env (settings.py 加载失败, 原因: %s)" % e
        d = {
            "llm_enabled": raw.get("LLM_ENABLED", "true").lower() == "true",
            "llm_base_url": raw.get("LLM_BASE_URL", ""),
            "llm_api_key": raw.get("LLM_API_KEY", ""),
            "llm_model": raw.get("LLM_MODEL", ""),
            "llm_temperature": float(raw.get("LLM_TEMPERATURE", "0.1")),
            "llm_max_tokens": int(raw.get("LLM_MAX_TOKENS", "4096")),
            "llm_timeout": float(raw.get("LLM_TIMEOUT", "120")),
        }
        return d, src, True


def mask_key(key: str) -> str:
    if not key:
        return "(空)"
    if len(key) <= 8:
        return "****"
    return f"{key[:6]}...{key[-4:]}"


# ==================== 2. HTTP 工具(OpenAI 兼容协议) ====================

def http_get_json(url, timeout):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def http_post_json(url, payload, api_key, timeout):
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def try_http(fn):
    """把 HTTP 异常翻译成可读消息,返回 (ok, 结果或错误说明)"""
    try:
        return True, fn()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:500]
        return False, f"HTTP {e.code}: {body}"
    except urllib.error.URLError as e:
        return False, f"网络错误(连不上/超时/DNS): {e.reason}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


# ==================== 3. 主流程 ====================

def main():
    ok, fail, warn = 0, 0, 0

    print("=" * 60)
    print("LLM 配置与连通性测试")
    print("=" * 60)

    # ---- 1. 配置加载 ----
    print("\n[1] 配置加载")
    d, src, is_manual = load_config()
    print(f"  来源: {src}")
    llm_enabled = d["llm_enabled"]
    base_url = d["llm_base_url"].rstrip("/")
    api_key = d["llm_api_key"]
    model = d["llm_model"]
    temperature = d["llm_temperature"]
    max_tokens = d["llm_max_tokens"]
    timeout = d["llm_timeout"]

    if is_manual:
        warn += 1
        print("  [WARN] settings.py 加载失败,改用手工解析 .env(只测连接,不测真实加载路径)")
    else:
        ok += 1
        print("  [PASS] settings.py 加载成功")

    print(f"  LLM_ENABLED    = {llm_enabled}")
    print(f"  LLM_BASE_URL   = {base_url or '(空!)'}")
    print(f"  LLM_MODEL      = {model or '(空!)'}")
    print(f"  LLM_API_KEY    = {mask_key(api_key)}")
    print(f"  LLM_TEMPERATURE= {temperature}")
    print(f"  LLM_MAX_TOKENS = {max_tokens}")
    print(f"  LLM_TIMEOUT    = {timeout}")

    if not llm_enabled:
        warn += 1
        print("  [WARN] LLM_ENABLED=false:引擎不会调用 LLM,下面仍测试网关连通性")
    if not base_url:
        fail += 1
        print("  [FAIL] LLM_BASE_URL 为空,请检查 .env")
        print("\n结果: %d 通过 / %d 失败 / %d 警告" % (ok, fail, warn))
        return 1
    if not model:
        fail += 1
        print("  [FAIL] LLM_MODEL 为空,请检查 .env")
        print("\n结果: %d 通过 / %d 失败 / %d 警告" % (ok, fail, warn))
        return 1

    models_url = base_url + "/models"
    chat_url = base_url + "/chat/completions"

    # ---- 2. GET /models ----
    print(f"\n[2] GET {models_url}")
    ok_get, res = try_http(lambda: http_get_json(models_url, timeout))
    if not ok_get:
        fail += 1
        print(f"  [FAIL] {res}")
    else:
        status, data = res
        ids = [m.get("id") for m in data.get("data", []) if isinstance(m, dict)]
        print(f"  [PASS] HTTP {status}, 网关可达, 模型列表 {len(ids)} 个")
        if ids:
            print(f"  模型: {', '.join(ids[:10])}{' ...' if len(ids) > 10 else ''}")
        if model in ids:
            print(f"  [PASS] 配置模型 '{model}' 在列表中")
        else:
            warn += 1
            print(f"  [WARN] 配置模型 '{model}' 不在列表中(可能是别名/网关不列全模型,继续测对话)")

    # ---- 3. POST /chat/completions ----
    prompt = "只返回一个 JSON 对象,键为 answer,值为 42。不要输出任何其他内容。"
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_tokens,
        "response_format": {"type": "json_object"},
    }
    print(f"\n[3] POST {chat_url} (model={model}, temperature={temperature}, max_tokens={max_tokens})")
    ok_post, res = try_http(lambda: http_post_json(chat_url, payload, api_key, timeout))
    if not ok_post:
        # 尝试去掉 response_format,区分"网关不支持 json 模式"与"完全连不上"
        if "response_format" in res or "json" in res.lower():
            warn += 1
            print(f"  [WARN] 带 response_format=json_object 失败: {res}")
            print("  [WARN] 尝试去掉 response_format 再发一次...")
            payload.pop("response_format", None)
            ok_post2, res2 = try_http(lambda: http_post_json(chat_url, payload, api_key, timeout))
            if ok_post2:
                print("  [PASS] 去掉 response_format 后对话成功")
                print("  [FAIL] 但引擎 llm_client.py 固定发送 response_format=json_object,")
                print("  [FAIL] 网关不支持则引擎标注会持续失败,建议换支持 json 模式的网关/模型")
                fail += 1
            else:
                fail += 1
                print(f"  [FAIL] 去掉 response_format 仍失败: {res2}")
        else:
            fail += 1
            print(f"  [FAIL] {res}")
    else:
        status, data = res
        try:
            content = (data["choices"][0]["message"]["content"] or "").strip()
        except (KeyError, IndexError, TypeError) as e:
            content = ""
            print(f"  [WARN] 响应结构异常(choices 缺失?): {e} -> {str(data)[:300]}")
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            parsed = None
        if parsed is not None:
            ok += 1
            print(f"  [PASS] HTTP {status}, 返回 JSON 可解析, answer={parsed.get('answer')}")
            print("  [PASS] 配置可用,引擎 LLM 标注路径应正常")
        else:
            warn += 1
            print(f"  [WARN] HTTP {status}, 但内容不是合法 JSON: {content[:200]!r}")
            print("  [WARN] 引擎依赖 JSON 解析,内容带解释文字时 llm_client 会尝试提取子串")

    print("\n" + "=" * 60)
    print("结果: %d 通过 / %d 失败 / %d 警告" % (ok, fail, warn))
    print("=" * 60)
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
