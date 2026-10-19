# -*- coding: utf-8 -*-
"""
统一配置加载器（零依赖，仅用标准库）。

部署时**无需修改 app.py**，只需二选一：
  1. 在同目录放一个 config.json（参考 config.example.json）；或
  2. 通过环境变量注入（适合 Docker / 容器，变量名见 ENV_MAP）。

配置优先级（高 -> 低）：
  环境变量  >  config.json  >  平台自动推导的默认值

可配置项
--------
host                 服务监听地址。本地默认 127.0.0.1；Docker 部署需改为 0.0.0.0 才能被容器外访问。
port                 服务监听端口，默认 5006。
ffmpeg               ffmpeg 可执行文件路径。留空（""）则走三级回退：bin/ffmpeg.exe -> imageio_ffmpeg -> 系统 ffmpeg。
bin_dir              存放 ffmpeg.exe 的目录，默认 <BASE>/bin。
downloads_dir        资源产物目录，默认 <BASE>/downloads（含 resources/、_collections/、.thumbnail_cache/）。
thumbnail_cache_dir  封面缓存目录，默认 <BASE>/.thumbnail_cache。

文章 / OCR（字幕 → 文章 / 硬字幕识别）相关
------------------------------------------
llm_base_url         OpenAI 兼容接口根地址（含 /v1）。默认本地 LM Studio（http://127.0.0.1:1234/v1）。
llm_api_key          模型服务密钥。⚠️ 严禁写入本文件或 config.docker.json（二者会进 git），
                     请写 config.json（已 gitignore）或设环境变量 RM_LLM_API_KEY。
llm_model            默认模型 id。
llm_timeout          单次生成超时秒数，默认 300（长文较慢）。
"""
import os
import json

BASE = os.path.dirname(os.path.abspath(__file__))


# 平台自动推导的默认值（config.json / 环境变量都缺省时使用）
DEFAULTS = {
    "host": "0.0.0.0",
    "port": 5006,
    "ffmpeg": "",                  # 留空 = 走 resolve_ffmpeg 三级回退
    "bin_dir": os.path.join(BASE, "bin"),
    "downloads_dir": os.path.join(BASE, "downloads"),
    "thumbnail_cache_dir": os.path.join(BASE, ".thumbnail_cache"),
    # ---- 文章 / OCR（LLM）----
    "llm_base_url": "http://127.0.0.1:1234/v1",
    "llm_api_key": "",             # 见模块 docstring：只放 config.json / 环境变量
    "llm_model": "qwen/qwen3.6-35b-a3b",
    "llm_timeout": 300,
}

# 环境变量名映射（统一前缀 RM_，避免与系统变量冲突）
ENV_MAP = {
    "host": "RM_HOST",
    "port": "RM_PORT",
    "ffmpeg": "RM_FFMPEG_BIN",
    "bin_dir": "RM_BIN_DIR",
    "downloads_dir": "RM_DOWNLOADS_DIR",
    "thumbnail_cache_dir": "RM_THUMBNAIL_CACHE_DIR",
    "llm_base_url": "RM_LLM_BASE_URL",
    "llm_api_key": "RM_LLM_API_KEY",
    "llm_model": "RM_LLM_MODEL",
    "llm_timeout": "RM_LLM_TIMEOUT",
}


def _load_json() -> dict:
    """读取同目录下的 config.json（不存在/解析失败则返回空 dict）。"""
    path = os.path.join(BASE, "config.json")
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def load_config() -> dict:
    cfg = dict(DEFAULTS)
    # 1) config.json 覆盖默认值
    for k, v in _load_json().items():
        if k in cfg and v not in (None, ""):
            cfg[k] = v
    # 2) 环境变量覆盖（容器部署最常用）
    for k, env in ENV_MAP.items():
        val = os.environ.get(env)
        if val:
            if k in ("port", "llm_timeout"):
                try:
                    val = int(val)
                except ValueError:
                    continue
            cfg[k] = val
    return cfg


# 模块加载时即解析出全局配置 dict
cfg = load_config()
