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

身份模式（决定用户从哪来）
------------------------
auth_mode            "gateway"    ：只采信可信代理（TRUSTED_PROXY_NETS）注入的 X-User-Email。
                                    RM 不存密码、不引导 admin——用户全在网关侧管理。
                     "standalone" ：启用 RM 自带用户模块（admin 引导 + 登录 + 用户管理），
                                    完全脱离网关也能跑；不认 X-User-Email。
                     "auto"（默认）：现状——可信 email > X-Session-Id > 匿名。
                                    不破现有部署，也是两种形态间的过渡桥。

⚠️ 切换 auth_mode 不需要迁移数据：数据只按「身份字符串」键存，无 auth_mode 痕迹。
   无损切换的唯一前提：独立模式账号一律归一化为 <用户名>@local，让身份串与网关时代一致。

以下三项**仅从环境变量读取**，绝不允许出现在 config.json（避免误提交）：
RM_ADMIN_USER        admin 账号名，默认 admin（实际身份串 = <名>@local）。
RM_ADMIN_PASSWORD    首次启动引导 admin 用的密码；未设则自动生成随机密码并打印到日志。
RM_SECRET            会话 cookie 签名密钥；未设则每次启动随机生成（重启即登出）。
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
    # ---- 身份模式（见模块 docstring）----
    "auth_mode": "auto",           # "auto" | "gateway" | "standalone"
    # ---- inbox watcher（方案 A 投递目录自动导入）----
    "RM_INBOX_DIR": "/app/inbox",            # 投递目录（容器内路径）
    "RM_INBOX_POLL_SEC": 10,                 # 扫描间隔（秒）
    "RM_INBOX_DEFAULT_OWNER": "admin@local", # meta 缺失时的兜底 owner
    "RM_INBOX_MAX_RETRY": 5,                 # 同组失败重试上限，超过移 .failed/
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
    "auth_mode": "RM_AUTH_MODE",
    # ---- inbox watcher ----
    "RM_INBOX_DIR": "RM_INBOX_DIR",
    "RM_INBOX_POLL_SEC": "RM_INBOX_POLL_SEC",
    "RM_INBOX_DEFAULT_OWNER": "RM_INBOX_DEFAULT_OWNER",
    "RM_INBOX_MAX_RETRY": "RM_INBOX_MAX_RETRY",
}

# ---- 机密项：只认环境变量，绝不从 config.json 读取（config.json 可能被误提交）----
ADMIN_USER = (os.environ.get("RM_ADMIN_USER") or "admin").strip() or "admin"      # 身份串 = <名>@local
ADMIN_PASSWORD = (os.environ.get("RM_ADMIN_PASSWORD") or "").strip()              # 空 = 首启自动生成
SECRET = (os.environ.get("RM_SECRET") or "").strip()                              # 空 = 启动时随机生成


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
            if k in ("port", "llm_timeout", "RM_INBOX_POLL_SEC", "RM_INBOX_MAX_RETRY"):
                try:
                    val = int(val)
                except ValueError:
                    continue
            cfg[k] = val
    return cfg


# 模块加载时即解析出全局配置 dict
cfg = load_config()
