# -*- coding: utf-8 -*-
"""
媒体资源库（Media Resource Manager）—— 后端服务
引擎: 资源池 + 回收站 + 共享 + 合集 + 字幕 OCR / 文章生成
接口（详见 index.html 与各路由）：
  GET  /                       -> 前端页面
  媒体库 / 回收站 / 共享 / 上传 / 目录导入 等 REST 端点
  字幕硬字幕 OCR、字幕->文章 生成端点
"""

import os

import re

import difflib

import time

import uuid

import json

import random

import shutil

import tempfile

import subprocess

import threading

import selectors

import hashlib

import hmac

import secrets

import base64

import io

import zipfile

import ipaddress

from collections import OrderedDict
from contextlib import contextmanager
from html.parser import HTMLParser

from fastapi import Depends, FastAPI, HTTPException, Header, Request, UploadFile, File, Form

from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response

from pydantic import BaseModel

BASE = os.path.dirname(os.path.abspath(__file__))

from config import cfg, ADMIN_USER, ADMIN_PASSWORD, SECRET, OO_JWT_SECRET, OO_SIGN_SECRET

BIN = cfg["bin_dir"]                       # 内含 ffmpeg.exe（可选，缺省走三级回退）

DOWNLOADS = cfg["downloads_dir"]

os.makedirs(DOWNLOADS, exist_ok=True)

# ==================== 身份模式（auth_mode）与独立用户模块 ====================
# gateway    : 只采信可信代理注入的 X-User-Email，RM 不存密码、不引导 admin。
# standalone : RM 自带账号体系（admin 引导 + 登录 + 用户管理），脱离网关可独立跑。
# auto（默认）: 现状（可信 email > X-Session-Id > 匿名），也是两形态间的过渡桥。
AUTH_MODE = (cfg.get("auth_mode") or "auto").strip().lower()
if AUTH_MODE not in ("auto", "gateway", "standalone"):
    print("[auth] 未知的 auth_mode=%r，回退 auto" % cfg.get("auth_mode"), flush=True)
    AUTH_MODE = "auto"

# 账号存储：落在 downloads/users/ 下（该目录已 gitignore），绝不进 config.json
ACCOUNTS_DIR = os.path.join(DOWNLOADS, "users")
ADMIN_FILE = os.path.join(ACCOUNTS_DIR, ".admin.json")
ACCOUNTS_FILE = os.path.join(ACCOUNTS_DIR, ".accounts.json")

# 会话签名密钥：未设 RM_SECRET 则每次启动随机生成（重启即登出，安全默认）
_SIGN_SECRET = SECRET or secrets.token_hex(32)

# ==================== ONLYOFFICE 集成开关（外部服务，默认关闭）====================
# 2026-11-25：ONLYOFFICE 是独立部署的第三方文档服务，不属于 RM 项目。
# 默认关闭；开启需管理员自行部署文档服务并设 RM_OO_ENABLED=1。
# 关闭时：前端不显示编辑按钮，且 /office/edit + /api/oo/* 全部 404（不只是 UI 隐藏）。
OO_ENABLED = bool(cfg.get("RM_OO_ENABLED", False))
# 服务端下载/回调短期签名密钥：显式 RM_OO_SIGN_SECRET > RM_SECRET > 启动随机
OO_SIGN_KEY = OO_SIGN_SECRET or SECRET or secrets.token_hex(32)
# 文档服务反连 RM 的内网地址与可信网段：由部署方按实际网络配置（默认值仅示意，不写死内网拓扑）
#  RM_OO_CALLBACK_HOST  : 文档服务用来访问 RM 的宿主地址（如 Docker 网桥网关 IP）
#  RM_OO_TRUSTED_NET    : 允许反连的 CIDR（默认 Docker 常见网桥段，部署时按实际覆盖）
OO_CALLBACK_HOST = (os.environ.get("RM_OO_CALLBACK_HOST") or "127.0.0.1").strip()
OO_TRUSTED_NET = (os.environ.get("RM_OO_TRUSTED_NET") or "172.17.0.0/16").strip()
# 编辑器 api.js 的对外地址（文档服务经网关暴露的域名）；部署方按实际覆盖
OO_APIJS_BASE = (os.environ.get("RM_OO_APIJS_BASE") or "").strip().rstrip("/")
# 文档服务「RM 可达」的内部地址（保存回调时抓 /cache/files/... 用），如 http://127.0.0.1:8082
# 与 OO_APIJS_BASE 是同一个服务的两个入口：浏览器走公网域名，RM 走回环端口，不能混用。
OO_INTERNAL_BASE = (os.environ.get("RM_OO_INTERNAL_BASE") or "").strip().rstrip("/")

def _oo_guard():
    """ONLYOFFICE 接口总闸：未开启直接 404（对未部署者完全隐形）。"""
    if not OO_ENABLED:
        raise HTTPException(404, "未找到")


def _oo_warn(msg, key=""):
    """ONLYOFFICE 相关告警：回调失败必须留痕，否则编辑器侧只看到"保存了"、库里没变。"""
    if OO_ENABLED:
        print(f"[oo] {msg}" + (f" (key={key})" if key else ""), flush=True)

def _oo_sign(payload: str, exp: int) -> str:
    """RM 自签短期票：HMAC-SHA256(rid|exp|email)，用于内网下载/回调防滥用。"""
    raw = f"{payload}|{exp}".encode("utf-8")
    return hmac.new(OO_SIGN_KEY.encode("utf-8"), raw, hashlib.sha256).hexdigest()

def _oo_sig_ok(payload: str, exp: int, sig: str) -> bool:
    if not sig or not exp or int(time.time()) > exp:
        return False
    return hmac.compare_digest(sig, _oo_sign(payload, exp))


# ONLYOFFICE 版本/幂等状态：用户级 state 文件（gitignore 的 downloads/users/ 下）
def _oo_state_path(sid):
    return os.path.join(user_root(sid), ".oo_state.json")


def _oo_state(sid):
    return _read_json(_oo_state_path(sid))


def _oo_version_get(sid, rid):
    """取 rid 当前版本号；不存在视为 0（首次打开 → v1）。"""
    v = (_oo_state(sid).get("versions") or {}).get(rid, 0)
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _oo_version_bump(sid, rid, body_key8="", size=0, ext="", title=""):
    """保存成功后版本号 +1，并追加版本历史记录。

    version 是逻辑计数（每次成功回写 +1，单调），body_key8 是内容寻址的物理版本。
    两者分开：回滚只换合集条目的 rel_path 指针、不 bump version，保证编辑 key 单调不撞车。
    不用 body_key8 目录数推算版本——目录会被 purge，且同内容 dedup 会复用目录。
    """
    d = _oo_state(sid)
    n = _oo_version_get(sid, rid) + 1
    d.setdefault("versions", {})[rid] = n
    if body_key8:
        entries = d.setdefault("version_log", {}).setdefault(rid, [])
        rec = {"v": n, "body_key8": body_key8, "ts": int(time.time()),
               "size": int(size or 0), "ext": ext or "", "title": title or ""}
        hit = next((e for e in entries if e.get("body_key8") == body_key8), None)
        if hit:
            hit.update(rec)          # 内容未变重复保存：更新时间，不重复占一条
        else:
            entries.append(rec)
        if len(entries) > 200:       # 防止 state 无限膨胀
            del entries[:-200]
    _write_json(_oo_state_path(sid), d)
    return n


def _oo_key_seen(sid, key):
    return key in ((_oo_state(sid).get("seen_keys") or {}))


def _oo_mark_key(sid, key):
    d = _oo_state(sid)
    seen = d.setdefault("seen_keys", {})
    seen[key] = int(time.time())
    # 只保留最近 500 个 key，防止无限增长
    if len(seen) > 500:
        for k in sorted(seen, key=lambda x: seen[x])[:len(seen) - 500]:
            seen.pop(k, None)
    _write_json(_oo_state_path(sid), d)


def _oo_docservice_hosts():
    """「文档服务自身」的已知主机名（小写）：既用于 SSRF 白名单，也用于内网地址重写。

    为什么要收集多个：浏览器侧只能访问公网域名（OO_APIJS_BASE），
    而回调 url 里的 host 就是文档服务的 baseurl —— 它会随访问入口变化：
    公网域名（正常部署）/ 容器名（未透传 X-Forwarded-* 时）/ 127.0.0.1（SSH 隧道调试）。
    """
    import urllib.parse
    hosts = {"onlyoffice-documentserver", "localhost", "127.0.0.1"}
    for u in (OO_APIJS_BASE, OO_INTERNAL_BASE):
        if not u:
            continue
        h = (urllib.parse.urlparse(u).hostname or "").lower()
        if h:
            hosts.add(h)
    return hosts


def _oo_is_trusted_ip(host: str) -> bool:
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(OO_TRUSTED_NET, strict=False)
    except ValueError:
        return False


def _oo_dl_host_allowed(url: str) -> bool:
    """callback 的 url 只允许指向文档服务自身或其所在可信网段，防 SSRF。"""
    import urllib.parse
    try:
        host = (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return False
    if not host:
        return False
    return host in _oo_docservice_hosts() or _oo_is_trusted_ip(host)


def _rewrite_dl_host(url: str) -> str:
    """把回调下载地址重写到「RM 自己够得着」的文档服务地址。

    典型部署里三方网络各不相同：
      · 浏览器 → 文档服务：公网域名（OO_APIJS_BASE，经网关反代）
      · 文档服务 → RM：宿主 gw_net IP（OO_CALLBACK_HOST）
      · RM → 文档服务：RM 常以 host 网络运行，既解析不了容器名、也连不上未发布的 80
    所以 callback url（其 host 来自文档服务 baseurl）必须改写成 RM_OO_INTERNAL_BASE
    （如 http://127.0.0.1:8082，文档服务只绑回环的宿主端口）。未配置该项则原样返回。
    """
    import urllib.parse
    if not OO_INTERNAL_BASE:
        return url
    try:
        p = urllib.parse.urlparse(url)
        host = (p.hostname or "").lower()
        if not (host in _oo_docservice_hosts() or _oo_is_trusted_ip(host)):
            return url
        t = urllib.parse.urlparse(OO_INTERNAL_BASE)
        if not t.netloc:
            return url
        return urllib.parse.urlunparse(p._replace(scheme=t.scheme or "http", netloc=t.netloc))
    except Exception:
        return url


# ============ ONLYOFFICE 新建：内置最小空白模板（零外部依赖，2026-11-25）============
# 设计要点：
#   1. docx/xlsx/pptx 是 OOXML zip，pdf 是最小合法 PDF；均用纯字符串拼装，不引第三方库。
#   2. 唯一标记写进 docProps/core.xml（dc:identifier=uuid + dcterms:created=毫秒时间），
#      使每次新建的字节不同 → sha256 不同 → rid 不同，避免内容去重把多份新文档合并成一份。
#   3. zip 条目时间固定为 1980-01-01，保证字节差异只来自 core.xml，便于复现与测试。
_OO_CREATE_EXT = {"word": ".docx", "cell": ".xlsx", "slide": ".pptx", "pdf": ".pdf"}
_OO_CREATE_LABEL = {"word": "文档", "cell": "表格", "slide": "演示文稿", "pdf": "PDF 文档"}

_XML_DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
_NS_PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
_NS_REL_DOC = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"

# 每个 documentType 的部件表；core.xml 由 _oo_core_xml() 动态注入，故此处不含它。
_OO_XML_PARTS = {
    "word": {
        "[Content_Types].xml": (
            _XML_DECL + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
            '</Types>'
        ),
        "_rels/.rels": (
            _XML_DECL + f'<Relationships xmlns="{_NS_PKG_REL}">'
            f'<Relationship Id="rId1" Type="{_NS_REL_DOC}/officeDocument" Target="word/document.xml"/>'
            f'<Relationship Id="rId2" Type="{_NS_PKG_REL}/metadata/core-properties" Target="docProps/core.xml"/>'
            '</Relationships>'
        ),
        "word/document.xml": (
            _XML_DECL + '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            '<w:body><w:p/></w:body></w:document>'
        ),
    },
    "cell": {
        "[Content_Types].xml": (
            _XML_DECL + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
            '</Types>'
        ),
        "_rels/.rels": (
            _XML_DECL + f'<Relationships xmlns="{_NS_PKG_REL}">'
            f'<Relationship Id="rId1" Type="{_NS_REL_DOC}/officeDocument" Target="xl/workbook.xml"/>'
            f'<Relationship Id="rId2" Type="{_NS_PKG_REL}/metadata/core-properties" Target="docProps/core.xml"/>'
            '</Relationships>'
        ),
        "xl/workbook.xml": (
            _XML_DECL + '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            f'xmlns:r="{_NS_REL_DOC}"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>'
        ),
        "xl/_rels/workbook.xml.rels": (
            _XML_DECL + f'<Relationships xmlns="{_NS_PKG_REL}">'
            f'<Relationship Id="rId1" Type="{_NS_REL_DOC}/worksheet" Target="worksheets/sheet1.xml"/>'
            '</Relationships>'
        ),
        "xl/worksheets/sheet1.xml": (
            _XML_DECL + '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData/></worksheet>'
        ),
    },
    "slide": {
        "[Content_Types].xml": (
            _XML_DECL + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>'
            '<Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>'
            '<Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>'
            '<Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>'
            '<Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>'
            '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
            '</Types>'
        ),
        "_rels/.rels": (
            _XML_DECL + f'<Relationships xmlns="{_NS_PKG_REL}">'
            f'<Relationship Id="rId1" Type="{_NS_REL_DOC}/officeDocument" Target="ppt/presentation.xml"/>'
            f'<Relationship Id="rId2" Type="{_NS_PKG_REL}/metadata/core-properties" Target="docProps/core.xml"/>'
            '</Relationships>'
        ),
        "ppt/presentation.xml": (
            _XML_DECL + '<p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
            f'xmlns:r="{_NS_REL_DOC}" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
            '<p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst>'
            '<p:sldIdLst><p:sldId id="256" r:id="rId2"/></p:sldIdLst>'
            '<p:sldSz cx="9144000" cy="6858000" type="screen4x3"/>'
            '<p:notesSz cx="6858000" cy="9144000"/></p:presentation>'
        ),
        "ppt/_rels/presentation.xml.rels": (
            _XML_DECL + f'<Relationships xmlns="{_NS_PKG_REL}">'
            f'<Relationship Id="rId1" Type="{_NS_REL_DOC}/slideMaster" Target="slideMasters/slideMaster1.xml"/>'
            f'<Relationship Id="rId2" Type="{_NS_REL_DOC}/slide" Target="slides/slide1.xml"/>'
            f'<Relationship Id="rId3" Type="{_NS_REL_DOC}/theme" Target="theme/theme1.xml"/>'
            '</Relationships>'
        ),
        "ppt/slideMasters/slideMaster1.xml": (
            _XML_DECL + '<p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
            f'xmlns:r="{_NS_REL_DOC}" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
            '<p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/>'
            '</p:nvGrpSpPr><p:grpSpPr/></p:spTree></p:cSld>'
            '<p:clrMap accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" '
            'accent5="accent5" accent6="accent6" bg1="lt1" bg2="lt2" folHlink="folHlink" '
            'hlink="hlink" tx1="dk1" tx2="dk2"/>'
            '<p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst>'
            '</p:sldMaster>'
        ),
        "ppt/slideMasters/_rels/slideMaster1.xml.rels": (
            _XML_DECL + f'<Relationships xmlns="{_NS_PKG_REL}">'
            f'<Relationship Id="rId1" Type="{_NS_REL_DOC}/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>'
            f'<Relationship Id="rId2" Type="{_NS_REL_DOC}/theme" Target="../theme/theme1.xml"/>'
            '</Relationships>'
        ),
        "ppt/slideLayouts/slideLayout1.xml": (
            _XML_DECL + '<p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
            f'xmlns:r="{_NS_REL_DOC}" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
            'type="blank" preserve="1"><p:cSld name="Blank">'
            '<p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
            '<p:grpSpPr/></p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>'
        ),
        "ppt/slideLayouts/_rels/slideLayout1.xml.rels": (
            _XML_DECL + f'<Relationships xmlns="{_NS_PKG_REL}">'
            f'<Relationship Id="rId1" Type="{_NS_REL_DOC}/slideMaster" Target="../slideMasters/slideMaster1.xml"/>'
            '</Relationships>'
        ),
        "ppt/slides/slide1.xml": (
            _XML_DECL + '<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
            f'xmlns:r="{_NS_REL_DOC}" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
            '<p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
            '<p:grpSpPr/></p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>'
        ),
        "ppt/slides/_rels/slide1.xml.rels": (
            _XML_DECL + f'<Relationships xmlns="{_NS_PKG_REL}">'
            f'<Relationship Id="rId1" Type="{_NS_REL_DOC}/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>'
            '</Relationships>'
        ),
        "ppt/theme/theme1.xml": (
            _XML_DECL + '<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="RM">'
            '<a:themeElements><a:clrScheme name="RM">'
            '<a:dk1><a:sysClr val="windowText" lastClr="000000"/></a:dk1>'
            '<a:lt1><a:sysClr val="window" lastClr="FFFFFF"/></a:lt1>'
            '<a:dk2><a:srgbClr val="44546A"/></a:dk2><a:lt2><a:srgbClr val="E7E6E6"/></a:lt2>'
            '<a:accent1><a:srgbClr val="4472C4"/></a:accent1><a:accent2><a:srgbClr val="ED7D31"/></a:accent2>'
            '<a:accent3><a:srgbClr val="A5A5A5"/></a:accent3><a:accent4><a:srgbClr val="FFC000"/></a:accent4>'
            '<a:accent5><a:srgbClr val="5B9BD5"/></a:accent5><a:accent6><a:srgbClr val="70AD47"/></a:accent6>'
            '<a:hlink><a:srgbClr val="0563C1"/></a:hlink><a:folHlink><a:srgbClr val="954F72"/></a:folHlink>'
            '</a:clrScheme><a:fontScheme name="RM">'
            '<a:majorFont><a:latin typeface="Calibri"/><a:ea typeface=""/><a:cs typeface=""/></a:majorFont>'
            '<a:minorFont><a:latin typeface="Calibri"/><a:ea typeface=""/><a:cs typeface=""/></a:minorFont>'
            '</a:fontScheme><a:fmtScheme name="RM"><a:fillStyleLst>'
            '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
            '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
            '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:fillStyleLst><a:lnStyleLst>'
            '<a:ln w="9525"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln>'
            '<a:ln w="9525"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln>'
            '<a:ln w="9525"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln></a:lnStyleLst>'
            '<a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle>'
            '<a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst>'
            '<a:bgFillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
            '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
            '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:bgFillStyleLst>'
            '</a:fmtScheme></a:themeElements><a:objectDefaults/><a:extraClrSchemeLst/></a:theme>'
        ),
    },
}


def _oo_core_xml(title, uid, ts):
    """OOXML core 属性：注入唯一标记，使同类型每次新建的字节不同。"""
    return (
        _XML_DECL + '<cp:coreProperties '
        'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        '<dc:title>' + html_escape(title) + '</dc:title>'
        '<dc:creator>RM</dc:creator>'
        '<cp:keywords>' + uid + '</cp:keywords>'
        '<dc:identifier>' + uid + '</dc:identifier>'
        '<dcterms:created xsi:type="dcterms:W3CDTF">' + ts + '</dcterms:created>'
        '<dcterms:modified xsi:type="dcterms:W3CDTF">' + ts + '</dcterms:modified>'
        '</cp:coreProperties>'
    )


def _oo_blank_ooxml(doc_type, title, uid, ts):
    """按 documentType 生成最小合法 OOXML zip 字节；zip 条目时间固定，唯一性只靠 core.xml。"""
    parts = dict(_OO_XML_PARTS[doc_type])
    parts["docProps/core.xml"] = _oo_core_xml(title, uid, ts)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name in sorted(parts):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, parts[name].encode("utf-8"))
    return buf.getvalue()


def _oo_blank_pdf(title, uid, ts):
    """生成最小合法 PDF；/Info 的 Title + CreationDate 注入唯一标记。"""
    def esc(s):
        return str(s).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    info = (f"/Title ({esc(title)}) /Author (RM) /Subject ({uid}) "
            f"/CreationDate (D:{ts.replace('-', '').replace(':', '').replace('T', '').rstrip('Z')}) "
            f"/Producer (RM)")
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << >> >>",
        ("<< " + info + " >>").encode("latin-1", "replace"),
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode("ascii") + body + b"\nendobj\n"
    xref_at = len(out)
    out += f"xref\n0 {len(objs) + 1}\n".encode("ascii")
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode("ascii")
    out += (f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R /Info 4 0 R >>\n"
            f"startxref\n{xref_at}\n%%EOF\n").encode("ascii")
    return bytes(out)


def _oo_blank_bytes(doc_type, title):
    """统一入口：返回 (bytes, 扩展名, 时间戳)。每次调用生成唯一内容。"""
    uid = uuid.uuid4().hex
    ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{time.time_ns() % 1_000_000:06d}Z"
    ext = _OO_CREATE_EXT[doc_type]
    if doc_type == "pdf":
        return _oo_blank_pdf(title, uid, ts), ext, ts
    return _oo_blank_ooxml(doc_type, title, uid, ts), ext, ts


def normalize_identity(name: str) -> str:
    """账号名 -> 身份字符串，一律归一化为 <name>@local。

    ⚠️ 这是「网关 / 独立双向无损切换」的硬前提：网关注入的身份形如 <name>@local，
    独立模式必须产出**完全相同**的字符串，user_hash 与 collections 键才能对齐；
    否则身份漂移 → 库显示为空（数据仍在磁盘，只是够不着）。
    """
    n = (name or "").strip()
    if not n:
        return ""
    return n if "@" in n else n + "@local"


def _pw_hash(password: str, salt: bytes = None) -> str:
    """口令哈希：stdlib pbkdf2_hmac（不引 bcrypt，避开原生编译依赖）。"""
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return "pbkdf2$%s$%s" % (salt.hex(), dk.hex())


def _pw_verify(password: str, stored: str) -> bool:
    """校验口令（恒定时间比较）。"""
    try:
        algo, salt_hex, dk_hex = (stored or "").split("$")
        if algo != "pbkdf2":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 bytes.fromhex(salt_hex), 100000)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _load_admin():
    return _read_json(ADMIN_FILE)


def _load_accounts():
    return _read_json(ACCOUNTS_FILE)


def _sign(value: str) -> str:
    """会话值签名（HMAC-SHA256），返回 <b64(value)>.<mac>。"""
    mac = hmac.new(_SIGN_SECRET.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()
    return "%s.%s" % (base64.urlsafe_b64encode(value.encode("utf-8")).decode().rstrip("="), mac)


def _unsign(token: str):
    """校验签名并还原原值；失败返回 None。"""
    try:
        raw, mac = (token or "").rsplit(".", 1)
        pad = "=" * (-len(raw) % 4)
        value = base64.urlsafe_b64decode(raw + pad).decode("utf-8")
        expect = hmac.new(_SIGN_SECRET.encode("utf-8"), value.encode("utf-8"),
                          hashlib.sha256).hexdigest()
        return value if hmac.compare_digest(expect, mac) else None
    except Exception:
        return None


def ensure_admin():
    """standalone 首次启动引导 admin 账号。

    已有 .admin.json → 跳过；否则用 RM_ADMIN_PASSWORD 建，
    env 未设则自动生成随机密码打印到日志（绝不空密码裸奔）。
    gateway / auto 模式不执行——那些模式下用户由网关或请求头提供。
    """
    if AUTH_MODE != "standalone":
        return
    d = _load_admin()
    if d.get("username"):
        return
    user = ADMIN_USER
    pw = ADMIN_PASSWORD or secrets.token_urlsafe(12)
    generated = not ADMIN_PASSWORD
    _write_json(ADMIN_FILE, {
        "username": user,
        "pw": _pw_hash(pw),
        "role": "admin",
        "created": time.time(),
        "generated": generated,
    })
    print("=" * 62, flush=True)
    print("[auth] standalone 模式：已创建 admin 账号", flush=True)
    print("[auth]   用户名 : %s" % user, flush=True)
    print("[auth]   身份串 : %s" % normalize_identity(user), flush=True)
    print("[auth]   密码   : %s%s" % (pw, "   <-- 随机生成，请登录后立即修改" if generated else ""),
          flush=True)
    print("=" * 62, flush=True)


ensure_admin()   # 模块加载即启动引导（等价于 startup 钩子）

def user_hash(sid):
    """由身份派生稳定目录 hash；None/空 视为固定匿名桶。"""
    key = (sid or "").strip() or "__anon__"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

def user_scope(sid):
    """相对 DOWNLOADS 的用户目录前缀（如 users/ab12cd34ef56gh78）。"""
    return "users/" + user_hash(sid)

def user_root(sid):
    """用户的物理根目录（绝对），不存在则创建。"""
    d = os.path.join(DOWNLOADS, "users", user_hash(sid))
    os.makedirs(d, exist_ok=True)
    return d

app = FastAPI(title="媒体资源库")

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRAG_RE = re.compile(r"\.f\d+\.[a-z0-9]+$")

MEDIA_EXT = (".mp4", ".mkv", ".webm", ".flv", ".mov", ".m4a", ".mp3", ".aac")

SIDE_EXT = (".srt", ".vtt", ".ass", ".xml", ".jpg", ".png", ".json", ".txt")

# 上传 / attach 分类用的扩展名（模块级，供上传入口与 attach 补挂共用）
SUB_EXTS  = (".srt", ".vtt", ".ass", ".lrc", ".txt")  # 字幕 / 文本衍生物
IMG_EXTS  = (".jpg", ".jpeg", ".png", ".webp")          # 封面
META_EXT  = (".json",)                                   # meta.json 衍生物（O3 解耦）

# ONLYOFFICE 文档主资源（2026-11-25）：独立于视频的资源大类，默认集成关闭。
# 注意 .txt/.json 已属 SUB_EXTS/META_EXT，不纳入本集合（避免上传分类被抢占）。
OFFICE_EXT = (".docx", ".doc", ".odt", ".rtf",
              ".xlsx", ".xls", ".ods", ".csv",
              ".pptx", ".ppt", ".odp", ".pdf")
# 扩展名 -> ONLYOFFICE documentType（word / cell / slide / pdf / diagram）
OFFICE_TYPE_MAP = {
    ".docx": "word", ".doc": "word", ".odt": "word", ".rtf": "word",
    ".xlsx": "cell", ".xls": "cell", ".ods": "cell", ".csv": "cell",
    ".pptx": "slide", ".ppt": "slide", ".odp": "slide",
    ".pdf": "pdf",
}
# 主资源扩展名合集：凡「挑主文件 / 内容去重 / 池内主文件判定」处统一用它。
# 之前这些点只写 MEDIA_EXT，导致 office 主资源入池后池内定位/去重全部失效。
MAIN_EXT = MEDIA_EXT + OFFICE_EXT

# 媒体类型推断（media_type 前瞻埋点，2026-10-22）：主体扩展名泛化，
# 让资源池不仅认识「视频」，也能标记「音频 / 文字 / 图片」主体。
VIDEO_EXT = (".mp4", ".mkv", ".webm", ".flv", ".mov")
AUDIO_EXT = (".m4a", ".mp3", ".aac")
TEXT_EXT  = (".txt", ".srt", ".vtt", ".ass", ".lrc", ".xml")

def media_type_of(path):
    """由文件扩展名推断 media_type：video / audio / text / image / office / other。"""
    ext = os.path.splitext(path or "")[1].lower()
    if ext in VIDEO_EXT:
        return "video"
    if ext in AUDIO_EXT:
        return "audio"
    if ext in TEXT_EXT:
        return "text"
    if ext in IMG_EXTS:
        return "image"
    if ext in OFFICE_EXT:
        return "office"
    return "other"

def _norm_stem(stem):
    """统一归一化主干：剥尾部 [BV号] → 剥 _字幕 标记 → 去分P序号前缀。

    上传 / attach 配对时用它跨「视频 / 字幕 / 封面 / meta」对齐文件名主干，
    使四类文件即使带不同后缀或下载工具标记也能准确归到同一资源主体。"""
    if not stem:
        return ""
    s = strip_bracket_suffix(stem)
    s = re.sub(r"_字幕$", "", s)
    s = normalize_stem(s)
    return s.strip()

TASK_REGISTRY_DIR = os.path.join(DOWNLOADS, "_tasks")

os.makedirs(TASK_REGISTRY_DIR, exist_ok=True)

TASK_REGISTRY_FILE = os.path.join(TASK_REGISTRY_DIR, "registry.json")

_task_registry_lock = threading.Lock()

_task_registry = None

COLLECTIONS_DIR = os.path.join(DOWNLOADS, "_collections")

COLLECTIONS_FILE = os.path.join(COLLECTIONS_DIR, "collections.json")

_collections_lock = threading.RLock()

_collections_cache = None  # 懒加载

_collections_mtime = None  # 文件 mtime，用于外部改动后自动失效缓存

def _load_collections():
    """读取合集数据。带 mtime 失效：当 collections.json 被外部修改（如手动修复脚本）
    时，下一次调用会自动重新加载，无需重启进程。"""
    global _collections_cache, _collections_mtime
    try:
        mtime = os.path.getmtime(COLLECTIONS_FILE)
    except OSError:
        mtime = None
    if _collections_cache is not None and _collections_mtime == mtime:
        return _collections_cache
    with _collections_lock:
        try:
            mtime2 = os.path.getmtime(COLLECTIONS_FILE)
        except OSError:
            mtime2 = None
        if _collections_cache is not None and _collections_mtime == mtime2:
            return _collections_cache
        try:
            with open(COLLECTIONS_FILE, encoding="utf-8") as f:
                _collections_cache = json.load(f)
            _collections_mtime = mtime2
        except Exception:
            if _collections_cache is None:
                _collections_cache = {}
    return _collections_cache

def _save_collections():
    with _collections_lock:
        os.makedirs(COLLECTIONS_DIR, exist_ok=True)
        tmp = COLLECTIONS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_collections_cache, f, ensure_ascii=False, indent=2)
        os.replace(tmp, COLLECTIONS_FILE)  # 原子替换，避免写一半崩溃损坏 json
        # 同步 mtime，避免「刚保存就被自己判定为外部改动」而下次无谓重载
        try:
            _collections_mtime = os.path.getmtime(COLLECTIONS_FILE)
        except OSError:
            pass

def _sid_key(sid):
    return (sid or "").strip() or "__anon__"

SHARES_DIR = os.path.join(DOWNLOADS, "_collections")

SHARES_FILE = os.path.join(SHARES_DIR, "shares.json")

_shares_cache = None

_shares_mtime = None

_shares_lock = threading.RLock()

BILI_SHARE_DEFAULT_TTL_DAYS = int(os.environ.get("BILI_SHARE_DEFAULT_TTL_DAYS", "30"))

def _load_shares():
    """读取共享令牌数据。带 mtime 失效（仿 _load_collections）。"""
    global _shares_cache, _shares_mtime
    try:
        mtime = os.path.getmtime(SHARES_FILE)
    except OSError:
        mtime = None
    if _shares_cache is not None and _shares_mtime == mtime:
        return _shares_cache
    with _shares_lock:
        try:
            mtime2 = os.path.getmtime(SHARES_FILE)
        except OSError:
            mtime2 = None
        if _shares_cache is not None and _shares_mtime == mtime2:
            return _shares_cache
        try:
            with open(SHARES_FILE, encoding="utf-8") as f:
                _shares_cache = json.load(f)
        except Exception:
            if _shares_cache is None:
                _shares_cache = {"tokens": {}, "config": {"default_ttl_days": BILI_SHARE_DEFAULT_TTL_DAYS},
                                 "per_user_config": {}, "accepted": {}}
        # 保证关键键存在
        _shares_cache.setdefault("tokens", {})
        _shares_cache.setdefault("config", {"default_ttl_days": BILI_SHARE_DEFAULT_TTL_DAYS})
        _shares_cache.setdefault("per_user_config", {})
        # accepted: {接收方身份: {token: {"added_at": ts}}} —— 「被共享」合集（接收方主动登记）
        _shares_cache.setdefault("accepted", {})
        _shares_mtime = mtime2
    return _shares_cache

def _save_shares():
    with _shares_lock:
        os.makedirs(SHARES_DIR, exist_ok=True)
        tmp = SHARES_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_shares_cache, f, ensure_ascii=False, indent=2)
        os.replace(tmp, SHARES_FILE)


# ---- 并发安全加固（O7）：跨进程文件锁 + 事务上下文 ----
# 背景：_collections_lock / _shares_lock 仅进程内串行；若以多 worker / 多进程部署，
# 各进程各自一份缓存 + 各自一把锁，会出现「读旧快照→覆盖写」的丢更新（_load_collections
# 的 mtime 失效反而放大该窗口）。这里用文件锁（posix flock；Windows 无 fcntl 则降级为
# 无操作，依赖单进程共享缓存保证）把「load→改→save」整段 RMW 在跨进程层面也串行化。
# 同一线程内的嵌套事务（如 ensure_trash_entry 内调 _ensure_trash_collection）靠线程局部
# 深度计数跳过重复加锁，避免同线程重入死锁。
try:
    import fcntl as _fcntl  # type: ignore
    _FCNTL = True
except ImportError:
    _fcntl = None
    _FCNTL = False

_COLLECTIONS_LOCKFILE = os.path.join(COLLECTIONS_DIR, ".collections.lock")
_SHARES_LOCKFILE = os.path.join(SHARES_DIR, ".shares.lock")

_collections_txn_depth = threading.local()
_shares_txn_depth = threading.local()


def _acquire_file_lock(path):
    if not _FCNTL:
        return None
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = open(path, "w")
    _fcntl.flock(fd, _fcntl.LOCK_EX)
    return fd


def _release_file_lock(fd):
    if fd is None:
        return
    try:
        _fcntl.flock(fd, _fcntl.LOCK_UN)
    finally:
        fd.close()


@contextmanager
def _collections_txn():
    """跨进程 + 进程内原子 RMW：持锁期间调用方做 load→改→save 一体。

    进程内用 RLock 把整段 RMW 串行化（避免 _load_collections 顶层 mtime 快检
    在锁外读到陈旧值后 reload 出「丢失其他线程内存改动」的缓存对象，save 时把改动冲掉）；
    跨进程用文件锁（posix flock；Windows 无 fcntl 则降级）。同一线程嵌套事务靠线程局部
    深度计数跳过重复文件锁，避免同线程重入死锁。

    关键正确性补丁：进入跨进程临界区（depth==0 且 fcntl 可用）时强制失效本进程 mtime 缓存，
    使下次 _load_collections 必从磁盘重载——否则多进程下两次写落在同一 mtime 粒度内时，
    缓存会判「未变」而返回陈旧数据，造成丢更新（flock 已串行 RMW 仍不够）。"""
    depth = getattr(_collections_txn_depth, "v", 0)
    fd = None
    with _collections_lock:
        if depth == 0 and _FCNTL:
            fd = _acquire_file_lock(_COLLECTIONS_LOCKFILE)
            # 拿到跨进程锁后、读文件前：其他进程可能已改写磁盘文件，mtime 粒度可能让其
            # 与本地缓存 mtime 相等，故强制置空缓存，强制下次从磁盘重载，杜绝陈旧读。
            global _collections_cache, _collections_mtime
            _collections_cache = None
            _collections_mtime = None
        _collections_txn_depth.v = depth + 1
        try:
            yield
        finally:
            _collections_txn_depth.v = depth
            _release_file_lock(fd)


@contextmanager
def _shares_txn():
    depth = getattr(_shares_txn_depth, "v", 0)
    fd = None
    with _shares_lock:
        if depth == 0 and _FCNTL:
            fd = _acquire_file_lock(_SHARES_LOCKFILE)
            # 同 _collections_txn：进入跨进程临界区强制失效本进程 mtime 缓存，防陈旧读丢更新
            global _shares_cache, _shares_mtime
            _shares_cache = None
            _shares_mtime = None
        _shares_txn_depth.v = depth + 1
        try:
            yield
        finally:
            _shares_txn_depth.v = depth
            _release_file_lock(fd)
        try:
            _shares_mtime = os.path.getmtime(SHARES_FILE)
        except OSError:
            pass

def _resolve_share(token):
    """校验令牌有效性：存在 + 未吊销 + 未过期 → 返回记录，否则 None。"""
    if not token:
        return None
    data = _load_shares()
    tok = data.get("tokens", {}).get(token)
    if not tok:
        return None
    if tok.get("revoked") or tok.get("locked"):
        return None
    exp = tok.get("expires_at")
    if exp is not None and exp < time.time():
        return None
    return tok

def _account_default_ttl(identity):
    """账号级默认有效期（天）。账号未单独设则回退全局默认。"""
    data = _load_shares()
    own = data.get("per_user_config", {}).get(identity)
    if isinstance(own, dict) and own.get("default_ttl_days") is not None:
        try:
            return int(own["default_ttl_days"])
        except (TypeError, ValueError):
            pass
    return BILI_SHARE_DEFAULT_TTL_DAYS

def _compute_expires_at(ttl_option, identity):
    """把有效期选项换算成 expires_at 时间戳。

    ttl_option:
      - "default"/"inherit" → 账号级默认（_account_default_ttl）
      - 正整数 / 数字串      → 该天数
      - "permanent"/"永久"/0/-1 → 永久（expires_at=None）
    返回 (expires_at, ttl_label)：ttl_label 为天数(int) 或 "permanent"。
    """
    if ttl_option in ("permanent", "永久", 0, "0", -1, "-1"):
        return None, "permanent"
    if ttl_option in ("default", None, "", "inherit"):
        days = _account_default_ttl(identity)
    else:
        try:
            days = int(ttl_option)
        except (TypeError, ValueError):
            days = _account_default_ttl(identity)
    if days in (0, -1):
        return None, "permanent"
    return time.time() + days * 86400, days

def _sid_collections(sid):
    """返回某用户的合集列表（list），确保存在「默认合集」。"""
    data = _load_collections()
    key = _sid_key(sid)
    if key not in data or not isinstance(data.get(key, {}).get("collections"), list):
        data[key] = {"collections": [{"id": "default", "name": "默认合集", "items": []}]}
        _save_collections()
    cols = data[key]["collections"]
    if not any(c.get("id") == "default" for c in cols):
        cols.insert(0, {"id": "default", "name": "默认合集", "items": []})
        _save_collections()
    return cols

TRUSTED_PROXY_NETS = [
    n.strip() for n in os.environ.get(
        "TRUSTED_PROXY_NETS", "127.0.0.1,::1,172.19.0.0/16"
    ).split(",") if n.strip()
]

_TRUSTED_NETS = []

for _n in TRUSTED_PROXY_NETS:
    try:
        _TRUSTED_NETS.append(ipaddress.ip_network(_n, strict=False))
    except ValueError:
        pass

def _is_trusted_proxy(ip: str) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _TRUSTED_NETS)

def _decode_punycode_email(email: str) -> str:
    """网关注入的 X-User-Email 因 HTTP 头必须 ASCII，中文用户名被 punycode 编码
    （如 包子呼叫 -> xn--uiruusnq9t）。这里把 local-part 解回中文，使合集分桶与
    whoami 回显显示原始用户名。非 punycode 或解码失败则原样返回。"""
    if not email or "@" not in email:
        return email
    local, _, domain = email.partition("@")
    if not local.lower().startswith("xn--"):
        return email
    ace = local[4:]  # 去掉 'xn--' 前缀；Python punycode codec 解码不含前缀
    try:
        decoded = ace.encode("ascii").decode("punycode")
    except (UnicodeError, ValueError):
        return email
    if not decoded or decoded == local:
        return email
    return f"{decoded}@{domain}"

def _fix_mojibake(s):
    """还原「UTF-8 字节被按 latin-1 解码」产生的乱码身份串。

    场景：客户端把中文身份（如 包子呼叫@local）作为 HTTP 头原样发送时，Web 框架按
    latin-1 解码得到 å\\x8c\\x85… 这类乱码，与网关 email 路径（punycode 解码）得到的正确
    身份不一致 → 同一账号的「被共享 / 合集归属」时有时无。
    仅当能无损 latin-1 编码回字节、再按 utf-8 解码成功时才替换；ASCII 与正常中文均原样返回。"""
    if not s:
        return s
    try:
        fixed = s.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return s
    return fixed

def current_identity(request: Request) -> str:
    """FastAPI 依赖：解析当前请求归属身份。按 auth_mode 三档切换：

    standalone : 只认 RM 自己下发的会话 cookie（登录所得），**忽略** X-User-Email。
                 身份串一律 <name>@local（见 normalize_identity），与网关时代键对齐。
    gateway    : 只认网关注入的 X-User-Email——**仅当来源 IP 处于 TRUSTED_PROXY_NETS 内才采信**，
                 防止绕过网关直连伪造身份；**忽略** X-Session-Id（杜绝自报身份）。
    auto（默认）: 可信 email > 浏览器级 X-Session-Id > None（落到 __anon__ 匿名桶，
                 由 _sid_key / user_hash 处理）。维持历史行为，也是两种形态间的过渡桥。

    用于合集归属、任务隔离等需要「稳定用户身份」的场景。"""
    if AUTH_MODE == "standalone":
        ident = _unsign(request.cookies.get("rm_session") or "") or ""
        return _fix_mojibake(ident) or None
    client_ip = request.client.host if request.client else ""
    email = (request.headers.get("x-user-email") or "").strip()
    if email and not _is_trusted_proxy(client_ip):
        email = ""          # 非可信来源：忽略伪造的 email 头
    if AUTH_MODE == "gateway":
        # 严格模式：只认网关注入的身份，不退回 X-Session-Id
        ident = _decode_punycode_email(email) or ""
        return _fix_mojibake(ident) or None
    sid = (request.headers.get("x-session-id") or "").strip()
    # 归一化身份串：把「UTF-8 被 latin-1 误解」的乱码还原，避免同一账号因来源头不同而分裂成两个身份
    ident = _decode_punycode_email(email) or sid or ""
    return _fix_mojibake(ident) or None

# standalone 模式下免登录的公开入口（登录自身、引导、调试回显、封面、共享取流/信息）
_STANDALONE_PUBLIC = (
    "/api/bootstrap", "/api/login", "/api/logout", "/api/whoami",
    "/api/thumbnail-cache/", "/api/files/", "/api/share/",
)


@app.middleware("http")
async def _standalone_auth_gate(request, call_next):
    """standalone 模式：无有效会话时，拒绝除公开入口外的所有 /api 调用（401）。

    背景：current_identity 解析不到身份时会落到**共享的 __anon__ 匿名桶**
    （_sid_key / user_hash 对空身份统一返回 __anon__）。单用户直连时无所谓，
    但独立多用户部署下会让所有未登录请求共用同一个桶 → 互相读到对方数据。
    这里统一在入口拦掉；登录、bootstrap、封面、共享取流等仍需免登录可用。
    """
    if AUTH_MODE == "standalone":
        p = request.url.path
        if p.startswith("/api/") and not p.startswith(_STANDALONE_PUBLIC):
            if not _unsign(request.cookies.get("rm_session") or ""):
                return JSONResponse({"detail": "未登录（standalone 模式需先登录）"},
                                    status_code=401)
    return await call_next(request)


@app.middleware("http")
async def _no_cache_html(request, call_next):
    """给 HTML 页面加 no-store，避免 index.html 被浏览器/反代缓存成旧版。

    背景：前端改版（尤其 OCR 占用态、刷新恢复）后，用户强刷前一直看到旧界面——
    StaticFiles 默认只发 last-modified/etag，浏览器协商缓存命中旧 HTML，
    表现为「新逻辑没生效」。仅对 text/html 禁止缓存，封面/字幕等静态资源照常缓存。
    """
    resp = await call_next(request)
    if (resp.headers.get("content-type") or "").startswith("text/html"):
        resp.headers["Cache-Control"] = "no-store, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
    return resp


def _entry_dedup_key(entry):
    """合集条目去重键：(vid, 序号, 标题)。

    用于识别「同一集视频被重下到不同任务目录」——此时 rel_path 不同，
    只按路径去重会失效、导致媒体库条目翻倍（19 个文件显示 38 个视频）。
    - 序号取文件名前缀（如 `008 【2026首发】...` → `008`）用于区分分P；
      ⚠️ 不能用文件名里的 `_pN` 后缀：下载工具不同批次可能写 `[BVxxxxxx]` 也可能写
      `[BVxxxxxx_p8]`，不稳定，会让「第1集」和「第8集」被误判为同一条。
    - 三者都取不到时返回 None，该条目不参与聚合（保守保留，不做删除）。
    """
    rp = (entry.get("rel_path") or "").replace("\\", "/")
    base = rp.rsplit("/", 1)[-1]

    # 公众号文章（2026-11-19）：dedup_key 用 resource_id（生产者按 url 派生的 r<sha256> 稳定），
    # 不用 title——作者改标题很常见，用 title 会让同一 rid 出现两条条目、旧版不回收。
    # 加 "article:" 前缀隔离，避免与视频 title 巧合碰撞；保持三元组结构兼容 803 处的解包。
    _st = (entry.get("source_type") or "").strip()
    _mt = (entry.get("media_type") or "").strip()
    if _st == "wechat_article" or _mt == "article":
        _rid = (entry.get("resource_id") or "").strip()
        if _rid:
            return ("", "", "article:" + _rid)
    # office 文档同理：按 resource_id 去重，标题改动不产生新条目（保证编辑回写复用同一 rid）
    if _st == "office" or _mt == "office":
        _rid = (entry.get("resource_id") or "").strip()
        if _rid:
            return ("", "", "office:" + _rid)

    m = re.match(r"^(\d{2,4})[\s._\-]", base)
    seq = m.group(1) if m else ""

    vid = (entry.get("vid") or "").strip()
    if not vid:
        mb = re.search(r"(BV[0-9A-Za-z]+|av\d+)", base)
        vid = mb.group(1) if mb else ""

    title = (entry.get("title") or "").strip()
    if not title:
        title = re.sub(r"\.(mp4|mkv|webm|m4a|mp3|flv)$", "", base, flags=re.I).strip()

    if not vid and not title:
        return None
    return (vid, seq, title)

RESOURCES_DIR = os.path.join(DOWNLOADS, "resources")

os.makedirs(RESOURCES_DIR, exist_ok=True)

def _resource_id_for(vid, seq):
    """集束主键：基于 (vid, 序号) 确定性派生，使「同一集视频」跨用户 / 跨次下载天然归一。
    不含标题（标题是展示字段，同一集不同标题归一为同一资源束，契合整集共享）。"""
    vid = (vid or "").strip()
    seq = (seq or "").strip()
    if not vid:
        return None
    return "r" + hashlib.sha256(f"{vid}|{seq}".encode()).hexdigest()[:15]

def _pool_dir(rid, body_key8):
    return os.path.join(RESOURCES_DIR, rid, body_key8)

def _pool_main_lookup(pool_dir):
    """Tier-1 资源池命中：池目录已存在主媒体文件则返回 (主文件绝对路径, [附加物相对路径])。"""
    if not os.path.isdir(pool_dir):
        return None, []
    media, side = [], []
    for fn in os.listdir(pool_dir):
        fp = os.path.join(pool_dir, fn)
        if not os.path.isfile(fp):
            continue
        if fn.lower().endswith(MAIN_EXT):
            media.append(fp)
        elif fn.lower().endswith(SIDE_EXT):
            side.append(os.path.relpath(fp, DOWNLOADS))
    if not media:
        return None, []
    main = max(media, key=os.path.getsize)
    extras = [os.path.relpath(f, DOWNLOADS) for f in media if f != main] + side
    return main, extras

def _move_staged_to_pool(main_abs, extras_rel, rid, body_key8):
    """把 staging 目录里的本集文件迁入资源池；返回 (池内主文件绝对路径, [池内附加物相对路径])。
    池内已存在同名文件（内容通常一致）→ 丢弃 staging 副本、保留池文件。"""
    pool_dir = _pool_dir(rid, body_key8)
    os.makedirs(pool_dir, exist_ok=True)

    def _mv(p):
        src = p if os.path.isabs(p) else os.path.join(DOWNLOADS, p)
        if not os.path.isfile(src):
            return None
        dst = os.path.join(pool_dir, os.path.basename(src))
        if os.path.abspath(src) == os.path.abspath(dst):
            return dst
        if os.path.exists(dst):
            try:
                os.remove(src)
            except OSError:
                pass
            return dst
        try:
            shutil.move(src, dst)
        except Exception:
            return src
        return dst

    new_main = _mv(main_abs) if main_abs else None
    new_extras = []
    for e in (extras_rel or []):
        ne = _mv(os.path.join(DOWNLOADS, e))
        if ne:
            new_extras.append(os.path.relpath(ne, DOWNLOADS))
    return new_main, new_extras

def _add_to_collection(sid, entry, target_cid="default", target_name=""):
    """把一条视频加入当前用户的指定合集。

    去重分两级：
      1) rel_path 完全相同 → 原样用非空字段补全（同一次任务的重复回调）；
      2) (vid, 序号, 标题) 相同但 rel_path 不同 → 视为「同一集换目录重下」，
         用新条目替换旧条目（新字段优先，旧值补齐空缺，如 duration），
         避免同一集在合集里留下两条。

    resource_id 稳定化（资源级共享的基石）：保证「同一集视频整体束」在合集里
    始终对应同一个 resource_id，即使重下到不同任务目录。
      1) 优先用 entry 自带；
      2) 否则继承同 dedup_key 已有条目的 resource_id；
      3) 否则新生成 uuid4。
    这样共享按 resource_id 授权时，未来衍生物/换目录重下都自动归入同一束。
    """
    _txn = _collections_txn()
    _txn.__enter__()
    try:
        cols = _sid_collections(sid)
        # 2026-11-16 修复（合集分组退化回归 ②）：用户显式指定的合集名（投递端 meta 的
        # collection_name）必须优先于 target_cid。此前先按 cid 找，而下载端 Step C 瘦身后
        # 已无本地 cid，meta 的 target_cid 恒为 "default" → 第一行直接命中「默认合集」，
        # 下面按名匹配 / 自动建同名合集两个分支永远短路，合集名被静默忽略（实测 131 集
        # 全部落进默认合集、目标合集 items=0）。现在 name 非空且非「默认合集」时先按名
        # 匹配、找不到则自动建；name 为空才回落到原本的 cid 语义（ingest/upload/import-dir
        # 等调用方都不传 name，行为完全不变）。
        _name = (target_name or "").strip()
        target = None
        if _name and _name != "默认合集":
            target = next((c for c in cols
                           if (c.get("name") or "").strip() == _name), None)
            if not target:
                # 两端 collections.json 互相独立、cid 各自生成：按名匹配不到就自动建同名
                # 合集（方案 A，2026-11-04），避免「静默回退默认合集」让用户以为没同步。
                new_cid = "c" + uuid.uuid4().hex[:10]
                target = {"id": new_cid, "name": _name, "items": []}
                cols.append(target)
                _save_collections()
                print(f"[collection] 自动建同名合集 owner={sid} name={_name} cid={new_cid}",
                      flush=True)
        if not target:
            target = next((c for c in cols if c["id"] == (target_cid or "default")), None)
        if not target:
            target = next((c for c in cols if c["id"] == "default"), None)
        if not target:
            raise RuntimeError(f"合集登记失败：owner={sid} 无可用合集")
        rel = entry.get("rel_path")

        # ---- resource_id 稳定化（资源池集束主键）----
        # 确定性：基于 (vid, 序号) 派生（见 _resource_id_for），不含标题。
        # 下载落盘目录与条目主键天然一致 → 跨用户 / 跨次下载归一、播放 / 共享无误。
        # 不使用「继承同 dedup_key 旧条目 rid」：旧格式（含标题）rid 与资源池目录命名不一致，
        # 会导致重下载后条目 rid ≠ 池目录 rid → serve 404。确定性派生保证同集始终同一 rid。
        _dk = _entry_dedup_key(entry)
        # 调用方已显式设置 resource_id（如本地文件内容哈希 rid）时尊重之；
        # 否则沿用原有确定性派生（vid|seq）或 uuid 兜底。
        res_id = entry.get("resource_id") or (
            _resource_id_for(_dk[0], _dk[1]) if _dk else uuid.uuid4().hex
        )
        entry["resource_id"] = res_id

        # 1) 完全同路径：补字段（保留旧 resource_id，不被覆盖）
        for it in target["items"]:
            if it.get("rel_path") == rel:
                for k, v in entry.items():
                    if v not in (None, ""):
                        it[k] = v
                it["resource_id"] = it.get("resource_id") or res_id
                _save_collections()
                remove_trash_entry(res_id, entry.get("body_key8"))  # 引用复活清回收站（精确）
                return None
        # 2) 同一集但换了目录/内容（重下/换任务目录/换内容）：替换旧条目，沿用其 resource_id
        key = _entry_dedup_key(entry)
        if key:
            for i, it in enumerate(target["items"]):
                if _entry_dedup_key(it) == key:
                    old_res = it.get("resource_id") or res_id
                    old_rel = it.get("rel_path")  # R3：被替换的旧版本 rel_path
                    merged = dict(it)
                    merged.update({k: v for k, v in entry.items() if v not in (None, "")})
                    merged["resource_id"] = old_res
                    target["items"][i] = merged
                    _save_collections()
                    remove_trash_entry(res_id, merged.get("body_key8"))  # 引用复活清回收站（精确）
                    return old_rel
        target["items"].append(entry)
        _save_collections()
        remove_trash_entry(res_id, entry.get("body_key8"))  # 新建引用：引用复活清回收站（精确）
        return None
    except Exception as e:
        # 不得静默吞掉：watcher 靠异常判定成败，吞了会「文件已入池并清理 inbox，
        # 合集里却没有条目」——无日志、无重试，数据像凭空消失（2026-11-04 排查）。
        print(f"[collection] ERROR 登记失败 owner={sid} "
              f"rid={entry.get('resource_id')} cid={target_cid} name={target_name}: {e}",
              flush=True)
        raise
    finally:
        _txn.__exit__(None, None, None)

def _title_from_filename(fname: str) -> str:
    """从下载工具产物文件名还原展示标题（去掉 ` [BVxxxxxx].mp4` 后缀）。"""
    name = os.path.splitext(fname)[0]
    name = re.sub(r"\s*\[[A-Za-z0-9_-]+\]\s*$", "", name)
    return name.strip() or fname

def _ensure_trash_collection():
    """确保 admin@local 下有 __trash__ 回收站系统合集（system:true）。返回其 dict。"""
    with _collections_txn():
        cols = _sid_collections("admin@local")
        trash = next((c for c in cols if c.get("id") == "__trash__"), None)
        if trash is None:
            trash = {"id": "__trash__", "name": "回收站", "items": [], "system": True}
            cols.append(trash)
            _save_collections()
        return trash

def _rid_of_item(it):
    """合集条目 → rid。优先 resource_id，缺失时退回 rel_path（resources/<rid>/...）。

    为什么需要兜底：姊妹接口 add_collection_item 只按 CollectionItemReq 建条目，而该模型
    没有 resource_id 字段——采集器/脚本走这条路添加的条目只有 rel_path。若引用计数只认
    resource_id，这类条目会被当成「无引用」，导致删掉一处引用就误判归零（别人还在引用
    却进了回收站），并误锁本人分享令牌。"""
    rid = (it.get("resource_id") or "").strip()
    if rid:
        return rid
    rel = (it.get("rel_path") or "").replace("\\", "/")
    if rel.startswith("resources/"):
        parts = rel.split("/")
        if len(parts) > 1 and parts[1]:
            return parts[1]
    return ""


def count_active_refs(rid):
    """全局 rid 级活跃引用计数：遍历所有 owner 的所有合集（排除 __trash__），
    统计该资源被引用的条目数。rid 归一走 _rid_of_item（兼容只有 rel_path 的条目）。"""
    if not rid:
        return 0
    data = _load_collections()
    n = 0
    for owner, v in data.items():
        for c in v.get("collections", []):
            if c.get("id") == "__trash__":
                continue
            for it in c.get("items", []):
                if _rid_of_item(it) == rid:
                    n += 1
    return n

def _count_active_refs_body(rid, body_key8):
    """(rid, body_key8) 级活跃引用计数：用于回收站列表精确显示某旧版本是否仍被引用。"""
    if not rid or not body_key8:
        return 0
    data = _load_collections()
    n = 0
    for owner, v in data.items():
        for c in v.get("collections", []):
            if c.get("id") == "__trash__":
                continue
            for it in c.get("items", []):
                rp = (it.get("rel_path") or "").replace("\\", "/")
                if rp.startswith("resources/" + rid + "/" + body_key8 + "/"):
                    n += 1
    return n

def ensure_trash_entry(rid, title, from_sid, rel_path=None, item=None, body_key8=None):
    """引用归零时把资源移入 admin 回收站（幂等：已存在则跳过）。物理文件不动。

    rel_path 保留最后删除的那条引用的【具体文件】路径；restore 时据此重建可 serve 的引用，
    避免恢复后条目指向目录（resources/<rid>/）导致无法播放。

    item 为该条目的【完整快照】：restore 时据此逐字还原（cover/subtitle/vid/subtitle_source/
    duration 等），避免只重建最小字段导致恢复后封面丢失、字幕绑定丢失（→ 文章入口消失、
    误显示 OCR 按钮）。"""
    if not rid:
        return
    with _collections_txn():
        trash = _ensure_trash_collection()
        bk = body_key8 or ""
        # 去重键 = (resource_id, body_key8)：rid 级条目（bk=""）与 (rid, 旧版本) 条目互不冲突，
        # 保证「换内容」产生的旧版本回收站条目不会误判为已存在而被跳过。
        if any(it.get("resource_id") == rid and (it.get("body_key8") or "") == bk for it in trash["items"]):
            return
        entry = {
            "resource_id": rid,
            "body_key8": bk,
            "rel_path": rel_path or ("resources/" + rid + "/"),
            "title": title or rid,
            "trashed_from": from_sid,
            "trashed_at": int(time.time()),
        }
        if isinstance(item, dict):
            snap = dict(item)
            snap["resource_id"] = rid
            snap["rel_path"] = entry["rel_path"]
            entry["item_snapshot"] = snap
        trash["items"].append(entry)
        _save_collections()

def remove_trash_entry(rid, body_key8=None):
    """引用复活（新增引用 / restore）时从回收站移除该条目（幂等）。

    body_key8 缺省（None）保持旧语义：移除该 rid 下所有回收站条目（rid 级引用归零场景）。
    传入 body_key8 时精确移除 (rid, body_key8) 条目，避免误删同 rid 的其它版本。"""
    if not rid:
        return
    with _collections_txn():
        data = _load_collections()
        cols = data.get("admin@local", {}).get("collections", [])
        trash = next((c for c in cols if c.get("id") == "__trash__"), None)
        if not trash:
            return
        before = len(trash["items"])
        if body_key8 is None:
            trash["items"] = [it for it in trash["items"] if it.get("resource_id") != rid]
        else:
            bk = body_key8 or ""
            trash["items"] = [it for it in trash["items"]
                              if not (it.get("resource_id") == rid and (it.get("body_key8") or "") == bk)]
        if len(trash["items"]) != before:
            _save_collections()

def _first_bili_sub(extras):
    """从附加文件列表中挑出官方字幕 TXT 的相对路径。"""
    if not extras:
        return ""
    for e in extras:
        if e.endswith("_字幕.txt"):
            return e
    return ""

def _auto_collect_into_library(sid, req, main_path, extras):
    """把下载成功的视频本体自动收录进当前用户的默认/指定合集（媒体库）。

    ⚠️ 单集下载的【两条】路径都必须调用，否则会出现「视频文件已就位、
    媒体库里却看不到」：
      1) 正常下载工具下载完成（函数末尾）；
      2) 「命中视频本体缓存」的早退分支（直接复用缓存文件后 return）——
         曾经漏掉这一条，表现为「跳过重复下载后默认合集没增加视频」。
    """
    try:
        if not main_path:
            return
        _vid = (re.search(r'BV[0-9A-Za-z]+', req.url or '') or [None])[0]
        _sub = _first_bili_sub(extras)
        _add_to_collection(sid, {
            "rel_path": os.path.relpath(main_path, DOWNLOADS),
            "title": _title_from_filename(os.path.basename(main_path)),
            "vid": _vid or "",
            "duration": None,
            "cover": getattr(req, "thumbnail", "") or "",
            "subtitle": _sub or "",
            "subtitle_source": "official" if _sub else "",
            "added_at": time.time(),
        }, target_cid=getattr(req, "target_cid", "") or "default")
    except Exception:
        pass

def strip_bracket_suffix(stem):
    """剥掉文件名主干尾部的方括号标记（如 ' [BVxxxxxx]'、' [BVxxxxxx]'）。

    背景：视频名由下载工具 outtmpl 生成，尾部带 [BV号]；而平台字幕由
    fetch_and_save_subtitle_txt 用清理后的标题生成，不带该标记。
    两者主干因此天然不一致，配对前必须先剥掉这个尾巴。
    """
    s = (stem or "").strip()
    prev = None
    while s and s != prev and s.endswith("]"):
        prev = s
        s = re.sub(r"\s*\[[^\[\]]*\]\s*$", "", s).strip()
    return s

def normalize_stem(stem):
    """归一化主干：先剥尾部 [BV号]，再去开头的分P序号前缀（'001 ' / '043 ' / 'NA '）。

    背景：批量下载用 outtmpl '%(playlist_index)03d %(title).50s [%(id)s]'，
    分P序号解析失败时下载工具会填 'NA'；而字幕名不带任何序号前缀。
    归一化后才能跨这两种命名对齐。
    """
    s = strip_bracket_suffix(stem)
    s = re.sub(r"^\s*(?:\d{1,4}|NA)\s+", "", s).strip()
    return s

def match_subtitle(stem, filename_set):
    """为视频主干 stem 在同目录文件名集合 filename_set 中找绑定字幕。

    匹配优先级（越靠前越可信）：
      1. 精确：{stem}_字幕.txt
      2. 剥离尾部 [BV号] 后精确：{stripped}_字幕.txt
      3. 归一化（去 [BV号] + 去序号前缀）后互为前缀（应对 'NA ' 占位与标题截断）
    注意：全角书名号「【】」属标题正文，不参与剥离。
    """
    if not stem:
        return ""
    fset = filename_set or set()
    cand = stem + "_字幕.txt"
    if cand in fset:
        return cand
    base = strip_bracket_suffix(stem)
    if base:
        cand = base + "_字幕.txt"
        if cand in fset:
            return cand
    nb = normalize_stem(stem)
    if nb:
        for f in sorted(fset):
            if not f.endswith("_字幕.txt"):
                continue
            ns = normalize_stem(f[:-len("_字幕.txt")])
            if ns and (nb.startswith(ns) or ns.startswith(nb)):
                return f
    return ""

def _subtitle_srt_rel(subtitle_rel):
    """由字幕 TXT 相对路径推导同名 .srt 相对路径；仅当该 .srt 真实存在时返回，否则返回 ""。
    用于前端「下载 SRT（带时间轴）」入口——.srt 由平台字幕/OCR 落盘时一并写出。"""
    if not subtitle_rel or not subtitle_rel.endswith(".txt"):
        return ""
    srt_rel = subtitle_rel[:-4] + ".srt"
    if os.path.isfile(os.path.join(DOWNLOADS, srt_rel)):
        return srt_rel
    return ""

def _find_existing_copy(rel_path, vid="", title=""):
    """媒体库自愈：当 rel_path 指向的视频文件已不存在时，在同一 owner
    （users/<hash>/）目录下寻找「同一视频」的其它副本，返回可用的 rel_path；
    找不到返回 ""。

    背景：同一视频重下到不同任务目录时，合集条目会指向最新目录（见
    _add_to_collection 的换目录替换逻辑）；若该目录随后被【外部】删除
    （手动清理磁盘、脚本误删、测试收尾 rm -rf 等），条目就悬空，前端
    永久显示「文件缺失」。此函数让媒体库在读取时自动改指仍然存在的副本。

    识别依据：优先用文件名里的 BV 号（最稳，跨标题变动仍可匹配）；
    退化时用展示标题逐一比对。
    """
    rp = (rel_path or "").replace("\\", "/")
    if rp and os.path.isfile(os.path.join(DOWNLOADS, rp)):
        return rp
    parts = rp.split("/")
    if len(parts) < 3 or parts[0] != "users":
        return ""
    root = os.path.join(DOWNLOADS, parts[0], parts[1])
    if not os.path.isdir(root):
        return ""
    bv = (vid or "").strip()
    if not bv:
        mb = re.search(r"(BV[0-9A-Za-z]+)", rp)
        bv = mb.group(1) if mb else ""
    want = (title or "").strip() or _title_from_filename(parts[-1])
    hits = []
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if not fn.lower().endswith(MEDIA_EXT):
                continue
            if bv:
                if bv not in fn:
                    continue
            elif _title_from_filename(fn) != want:
                continue
            hits.append(os.path.relpath(os.path.join(dirpath, fn), DOWNLOADS).replace("\\", "/"))
    if not hits:
        return ""
    if len(hits) == 1:
        return hits[0]

    def _score(p):
        d_abs = os.path.join(DOWNLOADS, os.path.dirname(p))
        try:
            sib = set(os.listdir(d_abs))
        except OSError:
            sib = set()
        stem = os.path.basename(p).rsplit(".", 1)[0]
        has_sub = 0 if match_subtitle(stem, sib) else 1   # 优先带规范字幕的副本
        dirty = 0 if len(sib) <= 1 else 1                 # 其次优先「只有视频本体」的干净目录
        return (has_sub, dirty, len(p), p)

    hits.sort(key=_score)
    return hits[0]

tasks: "OrderedDict[str, dict]" = OrderedDict()

tasks_lock = threading.Lock()

THUMBNAIL_CACHE_DIR = cfg["thumbnail_cache_dir"]

os.makedirs(THUMBNAIL_CACHE_DIR, exist_ok=True)


def _cache_cover_file(abs_path: str) -> str:
    """把资源池内的封面图复制进缩略图缓存目录，返回缓存文件名（md5(内容)[:12]+ext）。

    前端 `<img src="/api/thumbnail-cache/{it.cover}">` 只认**缓存文件名**，
    不认资源目录相对路径 —— 因此入池时必须回填缓存名，否则封面 404 显示「无封面」。
    失败返回空串（调用方按降级处理）。
    """
    try:
        if not abs_path or not os.path.isfile(abs_path):
            return ""
        os.makedirs(THUMBNAIL_CACHE_DIR, exist_ok=True)
        ext = os.path.splitext(abs_path)[1].lower() or ".jpg"
        with open(abs_path, "rb") as f:
            h = hashlib.md5(f.read()).hexdigest()[:12]
        name = f"{h}{ext}"
        dst = os.path.join(THUMBNAIL_CACHE_DIR, name)
        if not os.path.isfile(dst):
            shutil.copy2(abs_path, dst)
        return name
    except Exception:
        return ""

FNAME_TITLE_MAX = 50

def _safe_fname_title(title: str, max_chars: int = FNAME_TITLE_MAX) -> str:
    """清理文件名非法字符并截断到安全长度，避免 Linux 'File name too long' (Errno 36)。"""
    if not title:
        return "video"
    t = re.sub(r'[\/\\:*?"<>|]', '_', title).strip()
    if len(t) > max_chars:
        t = t[:max_chars].rstrip('_').strip() or t[:max_chars]
    return t or "video"

def _safe_upload_name(filename: str) -> str:
    """为上传文件生成安全文件名（去路径、替换非法字符、限制长度防 Errno 36）。"""
    name = os.path.basename(filename or "upload").strip().strip(".")
    name = re.sub(r'[\\/:*?"<>|]', "_", name)
    if not name:
        name = "upload"
    stem, ext = os.path.splitext(name)
    if len(name.encode("utf-8")) > 200:
        max_stem = 200 - len(ext.encode("utf-8"))
        stem = stem[:max_stem] if max_stem > 0 else stem
        name = stem + ext
    return name

def _uniq_path(path: str) -> str:
    """若 path 已存在，追加 _1/_2 直到不冲突。"""
    if not os.path.exists(path):
        return path
    d, n = os.path.split(path)
    stem, ext = os.path.splitext(n)
    i = 1
    while True:
        cand = os.path.join(d, f"{stem}_{i}{ext}")
        if not os.path.exists(cand):
            return cand
        i += 1


SESSIONS: "dict[str, dict]" = {}   # sid -> {"content": str, "login": bool, "time": float}（仅内存、不落盘）


def resolve_ffmpeg() -> str:
    """定位 ffmpeg 可执行文件。若 config 指定了 ffmpeg 路径则优先使用。"""
    ff = cfg.get("ffmpeg")
    if ff and os.path.isfile(ff):
        return ff
    bundled = os.path.join(BIN, "ffmpeg.exe")
    if os.path.isfile(bundled):
        return bundled
    try:
        import imageio_ffmpeg
        _ff = imageio_ffmpeg.get_ffmpeg_exe()
        if _ff and os.path.isfile(_ff):
            return _ff
    except Exception:
        pass
    # 最后尝试系统 PATH（ shutil.which 返回完整路径或 None）
    try:
        import shutil
        _which = shutil.which("ffmpeg")
        if _which:
            return _which
    except Exception:
        pass
    return ""  # 彻底找不到，调用方据此决定是否传 --ffmpeg-location

import urllib.parse

import hashlib

SUB_EXT = (".srt", ".vtt", ".ass", ".lrc")

def _resource_paths(owner, rid):
    """返回某 owner 合集中属于 rid 的全部物理文件路径集合
    （视频主文件 + 字幕 + 关联 AI 文章 + 正文图片）。用于共享令牌授权校验。

    匹配口径与 _find_resource 一致，走 _rid_of_item：只有 rel_path 的条目
    （采集器经 add_collection_item 建的）也能正确放行字幕/图片等衍生物，
    否则令牌能签发、主文件靠令牌快照兜底可下，附属文件却全部 404。"""
    cols = _sid_collections(owner)
    paths = set()
    for c in cols:
        for it in c.get("items", []):
            if _rid_of_item(it) == rid:
                if it.get("rel_path"):
                    paths.add(it["rel_path"].replace("\\", "/"))
                # P0-5（2026-11-19）：共享文章时放行正文图片。必须与 rel_path 平级放在
                # resource_id==rid 块内——文章无字幕，塞进 subtitle 分支等于没改。
                for im in (it.get("images") or []):
                    paths.add(str(im).replace("\\", "/"))
                if it.get("subtitle"):
                    sub = it["subtitle"].replace("\\", "/")
                    paths.add(sub)
                    arts = _article_rels_for_resource(_rid_of_item(it), it.get("body_key8"), owner)
                    if arts:
                        paths.update(arts)
    return paths

def _article_rel_for_subtitle(owner, subtitle_rel):
    """【C 方案兼容保留】给定 owner 与字幕 rel_path，反查其 AI 文章 .md 的 DOWNLOADS 相对路径；无则 None。
    优先按资源定位（resources/<rid>/<body>/users/<hash>/），无 rid/body 时回退旧 _articles/users/<hash>/。"""
    if not owner or not subtitle_rel:
        return None
    idx = _load_article_index(owner)
    sub_norm = subtitle_rel.replace("\\", "/")
    for stem, meta in idx.items():
        if (meta.get("rel_path") or "").replace("\\", "/") == sub_norm:
            _r, _b = meta.get("resource_id"), meta.get("body_key8")
            if _r and _b:
                p = os.path.join(_article_resource_md_dir(_r, _b, owner), stem + ".md")
            else:
                p = os.path.join(_article_art_dir(owner), stem + ".md")
            if os.path.isfile(p):
                return os.path.relpath(p, DOWNLOADS).replace("\\", "/")
    return None

def _file_response_or_inline(path, inline_html=False):
    """文件响应：.html 正文内联渲染（iframe 阅读器需要），其它文件保持下载语义。

    背景（2026-11-23）：FileResponse(filename=...) 会带 Content-Disposition: attachment，
    文章正文 html 被浏览器当下载 → iframe 空白（视频用 <video> 不受影响，故此前未暴露）。
    仅对 .html 去掉 filename；视频/字幕/图片等下载行为完全不变。
    """
    if inline_html and path.lower().endswith(".html"):
        return FileResponse(path, media_type="text/html; charset=utf-8")
    return FileResponse(path, filename=os.path.basename(path))


@app.get("/api/files/{name:path}")
def serve_file(name: str, share: str = None, sid: str = Depends(current_identity)):
    name = name.replace(os.sep, "/")
    # ---- 共享令牌分支（方案 A：登录 + 令牌授权只读）----
    if share:
        # 闸1：必须登录（防直连 5006 绕过网关匿名访问）
        if not sid:
            raise HTTPException(403, "需登录后访问")
        tok = _resolve_share(share)
        if not tok:
            raise HTTPException(404, "分享链接无效或已失效")
        owner = tok.get("owner")
        rid = tok.get("resource_id")
        # 闸3：逐文件校验——该文件必须属于令牌授权的 resource_id
        allowed = _resource_paths(owner, rid)
        # allowed 已含共享视频 + 字幕 + 对方(owner)的关联文章；此处仅补充放行
        # 「接收方自己基于共享字幕生成的文章」目录（_articles/users/<本用户hash>/），
        # 使被共享合集能展示接收方本人文章。仅收窄到文章目录，不开放视频目录，避免越权。
        self_art = "_articles/users/" + user_hash(sid) + "/"
        if (name in allowed
                or name == (tok.get("rel_path") or "").replace("\\", "/")
                or name.startswith(self_art)):
            path = os.path.abspath(os.path.join(DOWNLOADS, name))
            if not path.startswith(os.path.abspath(DOWNLOADS)) or not os.path.isfile(path):
                raise HTTPException(404, "文件不存在")
            return _file_response_or_inline(path, inline_html=True)  # 共享文章正文需内联渲染
        raise HTTPException(404, "文件不存在")
    # ---- 资源池文件：引用校验（请求者合集中须含该 resource_id）后放行 ----
    if name.startswith("resources/"):
        _parts = name.split("/")
        if len(_parts) >= 2:
            _rid = _parts[1]
            _ok = False
            # 仅用户可见合集授予播放权限；`__trash__` 是 admin 待清理暂存区，
            # 不属于播放授权依据（否则删引用后文件仍可被 admin serve，造成越权）。
            for c in _sid_collections(sid):
                if c.get("id") == "__trash__":
                    continue
                # 判据与 _find_resource 一致：只有 rel_path 的条目也要能播放/下载，
                # 否则采集器建的条目在媒体库里能看到却打不开。
                if any(_rid_of_item(it) == _rid for it in c.get("items", [])):
                    _ok = True
                    break
            if _ok:
                _pp = os.path.abspath(os.path.join(DOWNLOADS, name))
                if _pp.startswith(os.path.abspath(DOWNLOADS)) and os.path.isfile(_pp):
                    return _file_response_or_inline(_pp, inline_html=True)  # 文章正文内联渲染
        raise HTTPException(404, "文件不存在")

    # ---- 普通访问：仅本人 users/{hash}/ 目录（默认拒绝）----
    prefix = "users/" + user_hash(sid)
    if not name.startswith(prefix + "/"):
        raise HTTPException(404, "文件不存在")
    path = os.path.abspath(os.path.join(DOWNLOADS, name))
    if not path.startswith(os.path.abspath(DOWNLOADS)) or not os.path.isfile(path):
        raise HTTPException(404, "文件不存在")
    return FileResponse(path, filename=os.path.basename(path))


class DownloadZipReq(BaseModel):
    rel_paths: list = []


@app.post("/api/files/download-zip")
def download_zip(req: DownloadZipReq, sid: str = Depends(current_identity)):
    """打包下载选中文件（视频/图文/文档通用）。

    授权口径与 /api/files/{name} 资源池分支完全一致：仅放行 resources/ 前缀，
    且该文件所属 rid 必须出现在请求者可见合集（排除 __trash__），防越权。
    zip 内保留原文件名；同名文件加 (2)/(3) 后缀，避免覆盖。
    """
    if not sid:
        raise HTTPException(403, "需登录后下载")
    # 预先算出「该用户可见的所有 rid」，逐个文件复用，避免 N 次全量扫合集
    visible_rids = set()
    for c in _sid_collections(sid):
        if c.get("id") == "__trash__":
            continue
        for it in c.get("items", []):
            r = _rid_of_item(it)
            if r:
                visible_rids.add(r)

    buf = io.BytesIO()
    packed, used = [], {}
    try:
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for raw in (req.rel_paths or []):
                rel = str(raw or "").replace("\\", "/").strip()
                if not rel.startswith("resources/"):
                    continue
                parts = rel.split("/")
                if len(parts) < 3 or parts[1] not in visible_rids:
                    continue
                path = os.path.abspath(os.path.join(DOWNLOADS, rel))
                if not path.startswith(os.path.abspath(DOWNLOADS)) or not os.path.isfile(path):
                    continue
                name = os.path.basename(path)
                n = used.get(name, 0) + 1
                used[name] = n
                arcname = name if n == 1 else f"{os.path.splitext(name)[0]}({n}){os.path.splitext(name)[1]}"
                zf.write(path, arcname)
                packed.append(rel)
    except Exception as e:
        raise HTTPException(500, "打包失败：" + str(e))
    if not packed:
        raise HTTPException(404, "没有可下载的文件（需选中自己可见的资源）")
    buf.seek(0)
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="media-download.zip"'},
    )


# ==================== ONLYOFFICE 服务端接口（默认关闭）====================
# 由文档服务容器服务端发起，不带浏览器 cookie —— 鉴权靠「可信网段 + 短期 HMAC 签名」。
# 与 /api/files/{name:path} 的 share 分支完全隔离，不放宽其 sid 闸门。
_OO_MIME = {
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".doc": "application/msword",
    ".odt": "application/vnd.oasis.opendocument.text",
    ".rtf": "application/rtf",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".xls": "application/vnd.ms-excel",
    ".ods": "application/vnd.oasis.opendocument.spreadsheet",
    ".csv": "text/csv; charset=utf-8",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".ppt": "application/vnd.ms-powerpoint",
    ".odp": "application/vnd.oasis.opendocument.presentation",
    ".pdf": "application/pdf",
}


def _oo_main_path(owner, rid):
    """定位某用户合集中 rid 的主文件绝对路径；找不到返回 None。
    匹配口径与 _find_resource 一致走 _rid_of_item：
    条目的 resource_id 与 rel_path 里的 rid 可能因内容去重而不一致，
    因此只按条目引用取 rel_path，不强行要求 rel_path 片段等于传入 rid。"""
    for c in _sid_collections(owner):
        if c.get("id") == "__trash__":
            continue
        for it in c.get("items", []):
            if _rid_of_item(it) != rid:
                continue
            rp = (it.get("rel_path") or "").replace("\\", "/")
            if not rp.startswith("resources/") or os.path.splitext(rp)[1].lower() not in OFFICE_EXT:
                continue
            p = os.path.abspath(os.path.join(DOWNLOADS, rp))
            if p.startswith(os.path.abspath(DOWNLOADS)) and os.path.isfile(p):
                return p
    return None


@app.get("/api/oo/file")
def oo_file(rid: str, exp: int = 0, sig: str = "", email: str = "",
            sid: str = Depends(current_identity)):
    """文档服务端下载：owner 取「请求身份 or query email」，rid+owner 签名防滥用。

    为什么不能只靠 current_identity：ONLYOFFICE 服务端拉文件是纯服务端请求，
    不带 X-User-Email / X-Session-Id，identity 必为空。因此 owner 走 query，
    并由 sig 绑定（sig = HMAC("rid|owner")），伪造 email 会验签失败。
    """
    _oo_guard()
    email = (email or "").strip()
    if sid and email and normalize_identity(sid) != normalize_identity(email):
        raise HTTPException(403, "身份与签名归属不一致")
    owner = sid or email
    if not owner:
        raise HTTPException(403, "需登录")
    if not _oo_sig_ok(f"{rid}|{owner}", exp, sig):
        raise HTTPException(403, "签名无效或已过期")
    path = _oo_main_path(owner, rid)
    if not path:
        raise HTTPException(404, "资源不存在")
    if os.path.getsize(path) > 50 * 1024 * 1024:   # ONLYOFFICE 单文件硬限制
        raise HTTPException(413, "文件超过 50MB 限制")
    ext = os.path.splitext(path)[1].lower()
    return FileResponse(path, media_type=_OO_MIME.get(ext, "application/octet-stream"))


# ===== 文档只读预览（2026-11-26）：标准库解析 OOXML，不引 openpyxl/python-docx =====
_OO_NS_MAIN = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_OO_NS_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_OO_NS_P = "{http://schemas.openxmlformats.org/presentationml/2006/main}"
_OO_NS_A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
_OO_PREVIEW_MAX_ROWS = 200     # 防止大表格把浏览器撑爆
_OO_PREVIEW_MAX_COLS = 40
_OO_PREVIEW_MAX_CELLS = 20000


def _oo_parse_xlsx(path):
    """从 xlsx 提取 (sheet_name -> rows[][])。共享字符串 + inlineStr + 数值，跳过样式。"""
    import xml.etree.ElementTree as ET
    out = []
    with zipfile.ZipFile(path) as z:
        names = set(z.namelist())
        shared = []
        if "xl/sharedStrings.xml" in names:
            root = ET.fromstring(z.read("xl/sharedStrings.xml"))
            for si in root.findall(_OO_NS_MAIN + "si"):
                shared.append("".join(t.text or "" for t in si.iter(_OO_NS_MAIN + "t")))
        # 工作表顺序：优先 workbook.xml 的 sheet 次序
        sheet_files = [n for n in names if re.fullmatch(r"xl/worksheets/sheet\d+\.xml", n)]
        sheet_files.sort(key=lambda n: int(re.search(r"sheet(\d+)", n).group(1)))
        for sf in sheet_files:
            try:
                root = ET.fromstring(z.read(sf))
            except ET.ParseError:
                continue
            rows = []
            for row in root.iter(_OO_NS_MAIN + "row"):
                if len(rows) >= _OO_PREVIEW_MAX_ROWS:
                    break
                cells = []
                for c in row.findall(_OO_NS_MAIN + "c"):
                    t = (c.get("t") or "").strip()
                    v = c.find(_OO_NS_MAIN + "v")
                    if t == "inlineStr":
                        is_el = c.find(_OO_NS_MAIN + "is")
                        txt = "".join(x.text or "" for x in is_el.iter(_OO_NS_MAIN + "t")) if is_el is not None else ""
                    elif v is None:
                        txt = ""
                    elif t == "s":
                        try:
                            txt = shared[int(v.text or "0")]
                        except (ValueError, IndexError):
                            txt = ""
                    else:
                        txt = v.text or ""
                    cells.append(txt)
                    if len(cells) >= _OO_PREVIEW_MAX_COLS:
                        break
                rows.append(cells)
            out.append({"name": sf.split("/")[-1].replace(".xml", ""), "rows": rows})
    return out


def _oo_parse_docx(path):
    """从 docx 提取段落/表格文本，按文档顺序，保留换行。"""
    import xml.etree.ElementTree as ET
    with zipfile.ZipFile(path) as z:
        if "word/document.xml" not in z.namelist():
            return []
        root = ET.fromstring(z.read("word/document.xml"))
    lines = []
    body = root.find(_OO_NS_W + "body")
    if body is None:
        return []
    for el in body:
        tag = el.tag
        if tag == _OO_NS_W + "p":
            txt = "".join(t.text or "" for t in el.iter(_OO_NS_W + "t"))
            if txt.strip():
                lines.append(txt)
        elif tag == _OO_NS_W + "tbl":
            for tr in el.iter(_OO_NS_W + "tr"):
                cells = []
                for tc in tr.findall(_OO_NS_W + "tc"):
                    cells.append(" ".join(t.text or "" for t in tc.iter(_OO_NS_W + "t")))
                if any(c.strip() for c in cells):
                    lines.append(" | ".join(cells))
        if len(lines) >= _OO_PREVIEW_MAX_ROWS:
            break
    return lines


def _oo_parse_pptx(path):
    """从 pptx 提取每页文本（按 slide 编号排序）。"""
    import xml.etree.ElementTree as ET
    slides = []
    with zipfile.ZipFile(path) as z:
        names = [n for n in z.namelist() if re.fullmatch(r"ppt/slides/slide\d+\.xml", n)]
        names.sort(key=lambda n: int(re.search(r"slide(\d+)", n).group(1)))
        for n in names:
            try:
                root = ET.fromstring(z.read(n))
            except ET.ParseError:
                continue
            lines = []
            for p in root.iter(_OO_NS_A + "p"):
                txt = "".join(t.text or "" for t in p.iter(_OO_NS_A + "t"))
                if txt.strip():
                    lines.append(txt)
                if len(lines) >= 80:
                    break
            slides.append(lines)
    return slides


@app.get("/api/oo/preview")
def oo_preview(rid: str = "", sid: str = Depends(current_identity)):
    """文档只读预览数据（本人/可见资源，与 /api/files 同口径授权）。

    返回 JSON：{kind: sheet|doc|slides|pdf|unsupported, title, data}
    sheet: [{name, rows}]；doc: [段落文本]；slides: [[页内文本]]；pdf 前端走 iframe。
    """
    _oo_guard()
    if not sid:
        raise HTTPException(403, "需登录")
    rid = (rid or "").strip()
    path = _oo_main_path(sid, rid)
    if not path:
        raise HTTPException(404, "资源不存在或不可编辑")
    ext = os.path.splitext(path)[1].lower()
    title = os.path.splitext(os.path.basename(path))[0]
    if ext == ".pdf":
        return {"kind": "pdf", "title": title, "data": None}
    try:
        if ext in (".xlsx",):
            return {"kind": "sheet", "title": title, "data": _oo_parse_xlsx(path)}
        if ext in (".docx",):
            return {"kind": "doc", "title": title, "data": _oo_parse_docx(path)}
        if ext in (".pptx",):
            return {"kind": "slides", "title": title, "data": _oo_parse_pptx(path)}
    except Exception as e:
        raise HTTPException(422, "文档解析失败：" + str(e))
    return {"kind": "unsupported", "title": title, "data": None}


@app.get("/api/thumbnail-cache/{name:path}")
def serve_thumbnail_cache(name: str):
    """提供解析时缓存的本地封面图（避免 CDN 防盗链）。"""
    # 安全校验：只允许访问 .thumbnail_cache 目录
    path = os.path.join(THUMBNAIL_CACHE_DIR, name)
    path = os.path.abspath(path)
    if not path.startswith(os.path.abspath(THUMBNAIL_CACHE_DIR)) or not os.path.isfile(path):
        raise HTTPException(404, "封面缓存不存在")
    _ext = os.path.splitext(name)[1].lower()
    _mime = {".webp": "image/webp", ".png": "image/png", ".jpg": "image/jpeg",
             ".jpeg": "image/jpeg", ".gif": "image/gif"}.get(_ext, "image/webp")
    return FileResponse(path, media_type=_mime)  # 按实际扩展名推断，不再硬编码 webp

class CollectionReq(BaseModel):
    name: str = ""

class CollectionItemReq(BaseModel):
    rel_path: str = ""
    title: str = ""
    vid: str = ""
    duration: float = None
    cover: str = ""
    subtitle: str = ""

class MoveItemsReq(BaseModel):
    target_cid: str = ""
    rel_paths: list = []

class DeleteFilesReq(BaseModel):
    # 每个元素: {"rel_path": 视频相对路径, "subtitle": 字幕相对路径(可空)}
    # 字幕随视频绑定为整体，删除时一并删除
    items: list = []

@app.get("/api/whoami")
def whoami(request: Request):
    """调试端点：回显本次请求解析到的身份与来源，用于验证网关注入 X-User-Email 是否生效。
    仅回显请求自身信息，不触达他人数据。"""
    client_ip = request.client.host if request.client else ""
    raw_email = (request.headers.get("x-user-email") or "").strip()
    raw_sid = (request.headers.get("x-session-id") or "").strip()
    trusted = bool(raw_email) and _is_trusted_proxy(client_ip)
    if trusted:
        identity, source = _decode_punycode_email(raw_email), "email"
    elif raw_sid:
        identity, source = raw_sid, "session"
    else:
        identity, source = None, "anon"
    return {
        "identity": identity,
        "source": source,
        "client_ip": client_ip,
        "email_header": raw_email or None,
        "email_trusted": trusted,
        "trusted_nets": TRUSTED_PROXY_NETS,
    }

def _require_admin(request: Request) -> str:
    """admin 校验：身份串必须等于 admin 账号归一化后的身份（默认 admin@local）。

    与回收站三处 `if sid != "admin@local"` 用同一把尺子，standalone 登录后天然满足。"""
    sid = current_identity(request)
    if not sid or sid != normalize_identity(ADMIN_USER):
        raise HTTPException(403, "仅 admin 可操作")
    return sid


@app.get("/api/bootstrap")
def bootstrap(request: Request):
    """前端启动引导：下发身份模式、当前身份、是否需要登录。不触达他人数据。"""
    sid = current_identity(request)
    return {
        "auth_mode": AUTH_MODE,
        "identity": sid,
        "is_admin": bool(sid) and sid == normalize_identity(ADMIN_USER),
        "login_required": AUTH_MODE == "standalone" and not sid,
        "oo_enabled": OO_ENABLED,   # ONLYOFFICE 集成开关（默认 false，前端据此显隐编辑按钮）
    }


def _oo_jwt(payload: dict) -> str:
    """ONLYOFFICE config 签名（HS256，零依赖手写，与契约一致）。"""
    def b64(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
    header = b64(b'{"alg":"HS256","typ":"JWT"}')
    body = b64(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    unsigned = header + "." + body
    signature = b64(hmac.new(OO_JWT_SECRET.encode("utf-8"), unsigned.encode("ascii"),
                             hashlib.sha256).digest())
    return unsigned + "." + signature


@app.get("/office/edit", response_class=HTMLResponse, include_in_schema=False)
def office_edit(request: Request, rid: str = ""):
    """ONLYOFFICE 编辑入口页（默认关闭）。config + JWT 由服务端生成，密钥不下发浏览器。"""
    _oo_guard()
    sid = current_identity(request)
    if not sid:
        raise HTTPException(401, "需登录")
    if not OO_JWT_SECRET:
        raise HTTPException(503, "文档服务未配置 JWT 密钥")
    path = _oo_main_path(sid, rid)
    if not path:
        raise HTTPException(404, "资源不存在或不可编辑")
    ext = os.path.splitext(path)[1].lower()
    doc_type = OFFICE_TYPE_MAP.get(ext)
    if not doc_type:
        raise HTTPException(400, "该文档类型不支持在线编辑")
    # 共享只读：rid 出现在他人分享条目中则拒绝编辑
    for c in _sid_collections(sid):
        for it in c.get("items", []):
            if _rid_of_item(it) == rid and it.get("shared"):
                raise HTTPException(403, "共享资源只读")

    version = _oo_version_get(sid, rid) + 1
    key = f"{rid}_v{version}"
    exp = int(time.time()) + 3600
    sig = _oo_sign(f"{rid}|{sid}", exp)
    cb_sig = _oo_sign(f"cb|{key}|{sid}", exp)
    title = os.path.splitext(os.path.basename(path))[0]
    # 文件/回调 URL 走内网：文档服务容器可直连宿主 gw_net IP
    _cb_base = f"http://{OO_CALLBACK_HOST}:{cfg['port']}"
    # email 必须一并带上：文档服务端拉文件时不带任何身份头，owner 只能靠 query 传（与 callback 同口径），
    # 且 owner 已绑进 sig，改 email 会验签失败，不存在越权读取他人文件。
    file_url = (f"{_cb_base}/api/oo/file?rid={urllib.parse.quote(rid)}"
                f"&email={urllib.parse.quote(sid)}&exp={exp}&sig={sig}")
    cb_url = (f"{_cb_base}/api/oo/callback?key={urllib.parse.quote(key)}"
              f"&email={urllib.parse.quote(sid)}&exp={exp}&sig={cb_sig}")
    config = {
        "documentType": doc_type,
        "document": {
            "fileType": ext.lstrip("."),
            "key": key,
            "title": title,
            "url": file_url,
            "permissions": {"edit": True},
        },
        "editorConfig": {
            "callbackUrl": cb_url,
            "user": {"id": sid, "name": sid},
            "customization": {"autosave": False},
        },
    }
    if not OO_APIJS_BASE:
        raise HTTPException(503, "未配置文档服务编辑器地址（RM_OO_APIJS_BASE）")
    token = _oo_jwt(config)
    cfg_js = json.dumps(config, ensure_ascii=False).replace("</", "<\\/")
    _api_js = OO_APIJS_BASE + "/web-apps/apps/api/documents/api.js"
    # api.js 从文档服务域加载；config/token 由本页注入，浏览器不接触密钥
    return HTMLResponse(f"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>编辑 - {html_escape(title)}</title>
<!-- 高度必须给到 html/body：api.js 会把握手用的占位 div 替换成 <iframe height="100%">，
     直接挂在 body 下。若只给 #editor 定高，iframe 的 100% 无处可依 → 退回默认 150px，
     表现为编辑器被压成一条、下方一片空白。 -->
<style>html,body{{margin:0;height:100%;background:#f5f6f8}}#editor{{width:100%;height:100%}}</style>
</head><body><div id="editor"></div>
<script src="{_api_js}"></script>
<script>
var cfg = {cfg_js};
cfg.token = {json.dumps(token)};
new DocsAPI.DocEditor("editor", cfg);
</script></body></html>""")


def html_escape(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


class OOCreateReq(BaseModel):
    doc_type: str = ""      # word / cell / slide / pdf（即 documentType）
    title: str = ""
    cid: str = "default"


@app.post("/api/oo/create")
def oo_create(req: OOCreateReq, request: Request):
    """新建空白 Office 文档并入池（默认关闭）。造字节全在 RM 本地，不调用文档服务。"""
    _oo_guard()
    sid = current_identity(request)
    if not sid:
        raise HTTPException(401, "需登录")
    dt = (req.doc_type or "").strip().lower()
    if dt not in _OO_CREATE_EXT:
        raise HTTPException(400, "不支持的文档类型：" + dt)
    title = (req.title or "").strip() or f"未命名{_OO_CREATE_LABEL[dt]}"

    data, ext, _ts = _oo_blank_bytes(dt, title)
    h = hashlib.sha256(data).hexdigest()
    rid = "r" + h[:15]
    body_key8 = _body_key8_from_hash(h)
    stage_dir = os.path.join(user_root(sid), "_staging")
    os.makedirs(stage_dir, exist_ok=True)
    safe = _safe_upload_name(title + ext)
    dest = _uniq_path(os.path.join(stage_dir, safe))
    with open(dest, "wb") as w:
        w.write(data)
    try:
        _ingest_into_pool(sid, rid, body_key8, dest, [], title,
                          target_cid=(req.cid or "default"),
                          content_sha256=h, source_type="office", keep_versions=True)
        # 新建即 v1：版本历史从此刻起记录，前端只展示当前版本
        _oo_version_bump(sid, rid, body_key8=body_key8, size=len(data), ext=ext, title=title)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, "新建文档入池失败：" + str(e))
    return {"ok": True, "rid": rid, "title": title, "doc_type": dt,
            "file_type": ext.lstrip("."), "size": len(data)}


class OORenameReq(BaseModel):
    rid: str = ""
    name: str = ""


@app.post("/api/oo/rename")
def oo_rename(req: OORenameReq, sid: str = Depends(current_identity)):
    """重命名在线文档（2026-11-26）：display title、物理文件名、条目 rel_path 三者同步。

    为什么必须三者同步：卡片名取 entry['title']，而编辑器标题栏/下载名/预览标题都取
    物理文件名，编辑与下载又按 entry['rel_path'] 定位文件——只改其中一处会出现
    「卡片叫新名、打开还是旧名」或「指针指向不存在文件」的不一致。

    内容寻址不变：rid / body_key8 由文件内容哈希派生，改文件名不影响版本链。
    共享引用：同一物理文件可能被多个条目引用（内容去重），此时复制新文件并只改本人
    指针，避免断掉他人引用；仅 1 个引用时直接 rename。
    已有分享链接：同步本人令牌里的 rel_path/title，避免对方链接失效。
    版本历史：只更新当前版本的 title，历史版本保留当时名称。
    """
    _oo_guard()
    if not sid:
        raise HTTPException(401, "需登录")
    rid = (req.rid or "").strip()
    raw = (req.name or "").strip()
    if not rid:
        raise HTTPException(400, "rid 必填")
    if not raw:
        raise HTTPException(400, "新名称不能为空")
    with _collections_txn():
        data = _load_collections()
        cols = data.get(_sid_key(sid), {}).get("collections", [])
        target = None
        for c in cols:
            if c.get("id") == "__trash__":
                continue
            for it in c.get("items", []):
                if _rid_of_item(it) != rid:
                    continue
                rel = (it.get("rel_path") or "").replace("\\", "/")
                if not rel.startswith("resources/") or os.path.splitext(rel)[1].lower() not in OFFICE_EXT:
                    continue
                if it.get("shared"):
                    raise HTTPException(403, "共享资源只读，不能重命名")
                target = it
                break
            if target:
                break
        if target is None:
            raise HTTPException(404, "文档不存在或不可重命名")
        old_rel = (target.get("rel_path") or "").replace("\\", "/")
        old_abs = os.path.abspath(os.path.join(DOWNLOADS, old_rel))
        if not old_rel.startswith("resources/") or not old_abs.startswith(os.path.abspath(DOWNLOADS)) \
                or not os.path.isfile(old_abs):
            raise HTTPException(404, "物理文件不存在，无法重命名")
        ext = os.path.splitext(old_rel)[1].lower()
        stem = os.path.splitext(raw)[0] if raw.lower().endswith(ext) else raw
        safe = _safe_upload_name(stem + ext)
        new_stem = os.path.splitext(safe)[0].strip() or "document"
        # 重名不覆盖：同目录内自动加 _1/_2 后缀
        new_abs = _uniq_path(os.path.join(os.path.dirname(old_abs), new_stem + ext))
        new_rel = os.path.relpath(new_abs, DOWNLOADS).replace(os.sep, "/")
        used_stem = os.path.splitext(os.path.basename(new_abs))[0]
        # 跨全部用户统计该物理文件的引用数（排除回收站快照）
        refs = 0
        for _k, ud in data.items():
            for c in ud.get("collections", []):
                if c.get("id") == "__trash__":
                    continue
                for it in c.get("items", []):
                    if (it.get("rel_path") or "").replace("\\", "/") == old_rel:
                        refs += 1
        try:
            if refs > 1:
                shutil.copy2(old_abs, new_abs)   # 他人仍指向旧文件，只改本人指针
            else:
                os.rename(old_abs, new_abs)
        except OSError as e:
            raise HTTPException(500, f"重命名文件失败：{e}")
        target["rel_path"] = new_rel
        target["title"] = used_stem
        _save_collections()
    # 同步本人分享令牌（对方链接继续可用）
    shares = _load_shares()
    changed = False
    for _tk, rec in shares.get("tokens", {}).items():
        if rec.get("owner") == sid and (rec.get("rel_path") or "").replace("\\", "/") == old_rel:
            rec["rel_path"] = new_rel
            rec["title"] = used_stem
            changed = True
    if changed:
        _save_shares()
    # 版本记录：只更新当前版本的显示名
    d = _oo_state(sid)
    log = (d.get("version_log") or {}).get(rid) or []
    bk = (target.get("body_key8") or "").strip()
    hit = next((e for e in log if bk and e.get("body_key8") == bk), None)
    if hit is None and log:
        hit = log[-1]
    if hit and hit.get("title") != used_stem:
        hit["title"] = used_stem
        _write_json(_oo_state_path(sid), d)
    return {"ok": True, "rid": rid, "title": used_stem,
            "rel_path": new_rel, "file_name": os.path.basename(new_abs),
            "shared_refs_kept": refs > 1}


class OORollbackReq(BaseModel):
    rid: str = ""
    body_key8: str = ""


def _oo_version_rows(sid, rid):
    """汇总某文档的版本历史（后端事实，前端只消费当前版本那一条）。

    来源：_oo_state.json 的 version_log（权威记录） + 资源池物理目录（兜底兼容
    state 丢失/老数据）。每条带 physical_exists 与 is_current，前端据此标记。
    """
    log = ((_oo_state(sid).get("version_log") or {}).get(rid) or [])
    res_dir = os.path.join(RESOURCES_DIR, rid)
    # 物理目录兜底：state 里没有但池里有（例如早期版本、state 被重置）
    have = {str(e.get("body_key8") or "") for e in log if e.get("body_key8")}
    if os.path.isdir(res_dir):
        for sub in sorted(os.listdir(res_dir)):
            sd = os.path.join(res_dir, sub)
            if not os.path.isdir(sd) or sub in have:
                continue
            main, _extra = _pool_main_lookup(sd)
            if not main or os.path.splitext(main)[1].lower() not in OFFICE_EXT:
                continue
            log.append({"v": 0, "body_key8": sub, "ts": int(os.path.getmtime(main)),
                        "size": os.path.getsize(main), "ext": os.path.splitext(main)[1].lower(),
                        "title": ""})
    # 当前版本 = 活跃合集条目 rel_path 指向的 body_key8（单一指针，回滚改的就是它）
    cur_bk = ""
    for c in _sid_collections(sid):
        if c.get("id") == "__trash__":
            continue
        for it in c.get("items", []):
            if _rid_of_item(it) != rid:
                continue
            rp = (it.get("rel_path") or "").replace("\\", "/")
            parts = rp.split("/")
            if len(parts) >= 3 and parts[0] == "resources" and parts[1] == rid:
                cur_bk = parts[2]
            break
        if cur_bk:
            break
    rows = []
    for e in log:
        bk = str(e.get("body_key8") or "")
        main, _ex = _pool_main_lookup(os.path.join(res_dir, bk)) if bk else (None, [])
        ext_val = e.get("ext") or (os.path.splitext(main)[1].lower() if main else "")
        rows.append({
            "v": int(e.get("v") or 0), "body_key8": bk,
            "ts": int(e.get("ts") or 0), "size": int(e.get("size") or 0),
            "ext": ext_val,
            "title": e.get("title") or "",
            "physical_exists": bool(main),
            "is_current": bool(bk and bk == cur_bk),
        })
    rows.sort(key=lambda r: (r["v"], r["ts"]))
    return rows


@app.get("/api/oo/versions")
def oo_versions(rid: str = "", sid: str = Depends(current_identity)):
    """文档版本历史（只读）。仅本人文档；共享只读资源不给版本操作入口。"""
    _oo_guard()
    if not sid:
        raise HTTPException(401, "需登录")
    rid = (rid or "").strip()
    if not rid:
        raise HTTPException(400, "rid 必填")
    if not _oo_main_path(sid, rid):
        raise HTTPException(404, "资源不存在或不可编辑")
    for c in _sid_collections(sid):
        for it in c.get("items", []):
            if _rid_of_item(it) == rid and it.get("shared"):
                raise HTTPException(403, "共享资源只读")
    return {"rid": rid, "versions": _oo_version_rows(sid, rid)}


@app.get("/api/oo/versions/file")
def oo_version_file(rid: str = "", body_key8: str = "", sid: str = Depends(current_identity)):
    """下载指定历史版本的原文件（只读，仅本人文档）。共享只读资源不给。"""
    _oo_guard()
    if not sid:
        raise HTTPException(401, "需登录")
    rid = (rid or "").strip()
    bk = (body_key8 or "").strip()
    if not rid or not re.fullmatch(r"[0-9a-f]{8}", bk):
        raise HTTPException(400, "参数不合法")
    if not _oo_main_path(sid, rid):
        raise HTTPException(404, "资源不存在")
    for c in _sid_collections(sid):
        for it in c.get("items", []):
            if _rid_of_item(it) == rid and it.get("shared"):
                raise HTTPException(403, "共享资源只读")
    main, _ex = _pool_main_lookup(os.path.join(RESOURCES_DIR, rid, bk))
    if not main or os.path.splitext(main)[1].lower() not in OFFICE_EXT:
        raise HTTPException(404, "该版本不存在")
    return FileResponse(main, filename=os.path.basename(main),
                        media_type=_OO_MIME.get(os.path.splitext(main)[1].lower(),
                                                "application/octet-stream"))


@app.post("/api/oo/versions/rollback")
def oo_rollback(req: OORollbackReq, sid: str = Depends(current_identity)):
    """把指定历史版本设为当前版本（整体化：只换条目指针，不新增条目、不复制文件）。

    version 计数不回退——编辑器 key 保持单调，避免与已见过的回调 key 撞车；
    旧版本物理文件本就在资源池，回滚只是把 rel_path / body_key8 指过去。
    """
    _oo_guard()
    if not sid:
        raise HTTPException(401, "需登录")
    rid = (req.rid or "").strip()
    bk = (req.body_key8 or "").strip()
    if not rid or not bk:
        raise HTTPException(400, "rid 与 body_key8 必填")
    if not re.fullmatch(r"[0-9a-f]{8}", bk):
        raise HTTPException(400, "body_key8 格式不合法")
    if not _oo_main_path(sid, rid):
        raise HTTPException(404, "资源不存在或不可编辑")
    main, _ex = _pool_main_lookup(os.path.join(RESOURCES_DIR, rid, bk))
    if not main or os.path.splitext(main)[1].lower() not in OFFICE_EXT:
        raise HTTPException(404, "该版本不存在或不是可编辑文档")
    with _collections_txn():
        cols = _sid_collections(sid)
        hit = 0
        for c in cols:
            if c.get("id") == "__trash__":
                continue
            for it in c.get("items", []):
                if _rid_of_item(it) != rid:
                    continue
                if it.get("shared"):
                    raise HTTPException(403, "共享资源只读")
                it["rel_path"] = os.path.relpath(main, DOWNLOADS).replace(os.sep, "/")
                it["body_key8"] = bk
                it["restored_version_at"] = int(time.time())
                hit += 1
        if not hit:
            raise HTTPException(404, "无可用条目")
        _save_collections()
    return {"ok": True, "rid": rid, "body_key8": bk, "updated_items": hit}


class LoginReq(BaseModel):
    username: str = ""
    password: str = ""


@app.post("/api/login")
def login(req: LoginReq):
    """standalone 登录：校验 admin 或普通账号，成功后下发签名会话 cookie。"""
    if AUTH_MODE != "standalone":
        raise HTTPException(400, "当前不是 standalone 模式，无需登录（身份由网关提供）")
    name = (req.username or "").strip()
    pw = req.password or ""
    if not name or not pw:
        raise HTTPException(400, "请填写用户名和密码")
    ident = ""
    adm = _load_admin()
    if adm.get("username") and name == adm.get("username") and _pw_verify(pw, adm.get("pw", "")):
        ident = normalize_identity(adm["username"])
    else:
        acc = _load_accounts().get(name)
        if acc and _pw_verify(pw, acc.get("pw", "")):
            ident = normalize_identity(name)
    if not ident:
        raise HTTPException(401, "用户名或密码错误")
    resp = JSONResponse({"ok": True, "identity": ident,
                         "is_admin": ident == normalize_identity(ADMIN_USER),
                         "must_change_password": bool(adm.get("generated"))})
    resp.set_cookie("rm_session", _sign(ident), httponly=True, samesite="lax", path="/")
    return resp


@app.post("/api/logout")
def logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("rm_session", path="/")
    return resp


# ---- admin 用户管理（standalone 下 RM 自带账号体系）----

@app.get("/api/admin/users")
def admin_users(request: Request):
    _require_admin(request)
    out = []
    adm = _load_admin()
    if adm.get("username"):
        out.append({"username": adm["username"],
                    "identity": normalize_identity(adm["username"]), "role": "admin"})
    for u, d in _load_accounts().items():
        out.append({"username": u, "identity": normalize_identity(u),
                    "role": d.get("role", "user")})
    return {"ok": True, "users": out, "auth_mode": AUTH_MODE}


class UserCreateReq(BaseModel):
    username: str = ""
    password: str = ""


@app.post("/api/admin/users")
def admin_user_create(req: UserCreateReq, request: Request):
    """新增用户。身份串自动补 @local，保证与网关时代的存储键对齐。"""
    _require_admin(request)
    u = (req.username or "").strip()
    pw = (req.password or "").strip()
    if not u:
        raise HTTPException(400, "请填写用户名")
    if "@" in u:
        raise HTTPException(400, "用户名不要包含 @（系统会自动补 @local 后缀）")
    if u == ADMIN_USER:
        raise HTTPException(400, "该用户名保留给 admin")
    generated = not pw
    if generated:
        pw = secrets.token_urlsafe(10)
    acc = _load_accounts()
    acc[u] = {"pw": _pw_hash(pw), "role": "user", "created": time.time()}
    _write_json(ACCOUNTS_FILE, acc)
    return {"ok": True, "username": u, "identity": normalize_identity(u), "password": pw,
            "generated": generated,
            "note": "身份串已补 @local；若该用户曾在网关下使用同名账号，其历史数据可直接取回"}


@app.post("/api/admin/users/{u}/reset")
def admin_user_reset(u: str, req: UserCreateReq, request: Request):
    _require_admin(request)
    acc = _load_accounts()
    if u not in acc:
        raise HTTPException(404, "用户不存在")
    pw = (req.password or "").strip() or secrets.token_urlsafe(10)
    acc[u]["pw"] = _pw_hash(pw)
    _write_json(ACCOUNTS_FILE, acc)
    return {"ok": True, "username": u, "password": pw}


@app.delete("/api/admin/users/{u}")
def admin_user_delete(u: str, request: Request):
    """删除登录账号。注意：只删账号，不动资源——其数据仍在 users/<hash>/ 桶里。"""
    _require_admin(request)
    acc = _load_accounts()
    if u not in acc:
        raise HTTPException(404, "用户不存在")
    acc.pop(u, None)
    _write_json(ACCOUNTS_FILE, acc)
    return {"ok": True, "username": u,
            "note": "仅删除登录账号；资源仍留在 users/<hash> 桶中，用同名重建账号即可取回"}


class PwChangeReq(BaseModel):
    old_password: str = ""
    new_password: str = ""


@app.post("/api/admin/password")
def admin_change_password(req: PwChangeReq, request: Request):
    """admin 自助改密（首启随机生成的密码应尽快改掉）。"""
    _require_admin(request)
    adm = _load_admin()
    if not _pw_verify(req.old_password or "", adm.get("pw", "")):
        raise HTTPException(401, "原密码错误")
    if not (req.new_password or "").strip():
        raise HTTPException(400, "新密码不能为空")
    adm["pw"] = _pw_hash(req.new_password)
    adm["generated"] = False
    _write_json(ADMIN_FILE, adm)
    return {"ok": True}


class ShareCreateReq(BaseModel):
    resource_id: str = ""
    ttl_option: str = "default"   # "default" / 数字天数 / "permanent"

def _find_resource(owner, rid):
    """在 owner 合集里找 rid 匹配的资源，返回 (item, allowed_paths)。
    找不到返回 (None, None)。allowed_paths 含主文件 + 字幕等衍生物。

    匹配口径统一走 _rid_of_item（resource_id 优先，rel_path 兜底）：采集器/脚本经
    add_collection_item 建的条目只有 rel_path，若此处只认 resource_id，这类资源
    无法签发分享（POST /api/share 报「资源不存在或不属于你」）、也拿不到分享页
    元数据与 OCR 入口。"""
    if not rid:
        return None, None
    cols = _sid_collections(owner)
    for c in cols:
        for it in c.get("items", []):
            if _rid_of_item(it) == rid:
                paths = set()
                if it.get("rel_path"):
                    paths.add(it["rel_path"].replace("\\", "/"))
                if it.get("subtitle"):
                    paths.add(it["subtitle"].replace("\\", "/"))
                return it, paths
    return None, None

SHARED_COLLECTION_ID = "__shared__"

def _shared_with_me_collection(identity):
    """构造接收方视角的「被共享」虚拟合集（未加入过则返回 None）。

    条目来自 shares.json 的 accepted[identity]（接收方在分享页主动登记）。
    逐条实时 join 令牌与 owner 合集，派生四种状态：
      active   正常（可播放/下载）
      expired  已过期（owner 设定的有效期已到）
      revoked  owner 已关闭共享（吊销令牌）
      missing  令牌已被彻底删除（数据清理后的残留引用）
    失效条目一律保留（灰显），由接收方自行「移出」或一键「清理失效」。
    """
    if not identity:
        return None
    data = _load_shares()
    accepted = (data.get("accepted") or {}).get(identity) or {}
    if not accepted:
        return None
    tokens = data.get("tokens") or {}
    now = time.time()
    items = []
    for token, meta in accepted.items():
        tok = tokens.get(token)
        if tok:
            if tok.get("revoked"):
                status = "revoked"
            elif tok.get("expires_at") is not None and tok["expires_at"] < now:
                status = "expired"
            else:
                status = "active"
        else:
            status = "missing"
        owner = (tok or {}).get("owner")
        rid = (tok or {}).get("resource_id")
        src = None
        if owner and rid:
            src, _ = _find_resource(owner, rid)
        if not src:
            # 兜底：owner 侧条目已删（或令牌被清理）时退用令牌快照，保证不凭空消失
            if not tok:
                continue
            src = {"title": tok.get("title", ""), "rel_path": tok.get("rel_path", "")}
        rel = (src.get("rel_path") or "").replace("\\", "/")
        sub = (src.get("subtitle") or "").replace("\\", "/")
        exists = bool(rel) and os.path.isfile(os.path.join(DOWNLOADS, rel))
        # 关联 AI 文章：优先接收方自己基于该字幕生成的文章（落在接收方目录），
        # 其次回退共享者(owner)已生成的文章（共享视频也能生成文章，自己没写时看对方的）。
        arts_owner = _article_rels_for_resource(rid, src.get("body_key8"), owner) if owner else []
        arts_self = _article_rels_for_resource(rid, src.get("body_key8"), identity) if (identity and identity != owner) else []
        art_rel_owner = arts_owner[0] if arts_owner else ""
        art_rel_self = arts_self[0] if arts_self else ""
        # 接收方优先展示"自己基于共享字幕生成的文章"；自己没生成时回退展示对方的文章
        art_rel = art_rel_self or art_rel_owner
        art_owner = identity if art_rel_self else (owner if art_rel_owner else None)
        items.append({
            # 与普通合集条目同构的基础字段（前端卡片/播放器复用）
            "title": src.get("title") or (tok or {}).get("title") or rel,
            "rel_path": rel,
            "subtitle": sub,
            "subtitle_srt": (src.get("subtitle_srt") or _subtitle_srt_rel(sub)),
            "subtitle_source": src.get("subtitle_source", ""),
            "article_rel": (art_rel or ""),
            "article_filename": (os.path.basename(art_rel) if art_rel else ""),
            "article_bold": (_article_bold_for(art_owner, os.path.splitext(os.path.basename(art_rel))[0], sub) if art_rel else None),
            "cover": src.get("cover", ""),
            "duration": src.get("duration"),
            "vid": src.get("vid", ""),
            "resource_id": rid,
            "stale": not exists,
            # 文章字段透传（2026-11-19）：接收方「被共享」里要认出文章卡片、渲染 iframe、
            # 并为正文相对图片补 ?share= token，前端 P1 依赖这几个字段。src 缺失时安全降级为空。
            "source_type": src.get("source_type", ""),
            "media_type": src.get("media_type", ""),
            "url": src.get("url", ""),
            "images": list(src.get("images") or []),
            # 发布日期 / 内容子类型回显（2026-11-23）：接收方卡片显示/筛选的数据源。
            "published_at": src.get("published_at", ""),
            "content_type": src.get("content_type", ""),
            # 共享扩展字段
            "shared": True,
            "share_token": token,
            "share_owner": owner,
            "share_status": status,
            "expires_at": (tok or {}).get("expires_at"),
            "ttl_label": "permanent" if (tok or {}).get("ttl_days") in (None, "permanent") else (tok or {}).get("ttl_days"),
            "added_at": (meta or {}).get("added_at"),
        })
    if not items:
        return None
    items.sort(key=lambda x: x.get("added_at") or 0, reverse=True)
    return {"id": SHARED_COLLECTION_ID, "name": "📥 被共享", "shared": True, "items": items}

@app.post("/api/share")
def create_share(req: ShareCreateReq, sid: str = Depends(current_identity)):
    """为某 resource_id 生成只读分享令牌（链接）。仅 owner 可对自己的资源生成。"""
    if not sid:
        raise HTTPException(401, "需登录")
    if not req.resource_id:
        raise HTTPException(400, "resource_id 不能为空")
    item, _ = _find_resource(sid, req.resource_id)
    if not item:
        raise HTTPException(404, "资源不存在或不属于你")
    expires_at, ttl_label = _compute_expires_at(req.ttl_option, sid)
    token = uuid.uuid4().hex
    data = _load_shares()
    data["tokens"][token] = {
        "owner": sid,
        "resource_id": req.resource_id,
        "rel_path": (item.get("rel_path") or "").replace("\\", "/"),
        "title": item.get("title", ""),
        "created_at": time.time(),
        "ttl_days": None if ttl_label == "permanent" else ttl_label,
        "expires_at": expires_at,
        "revoked": False,
        "locked": False,
        "access_count": 0,
    }
    _save_shares()
    return {"ok": True, "token": token, "link": f"/share/{token}",
            "expires_at": expires_at, "ttl_label": ttl_label}

@app.get("/api/share/config")
def get_share_config(sid: str = Depends(current_identity)):
    if not sid:
        raise HTTPException(401, "需登录")
    data = _load_shares()
    own = data.get("per_user_config", {}).get(sid)
    return {"identity": sid,
            "default_ttl_days": (own or {}).get("default_ttl_days", BILI_SHARE_DEFAULT_TTL_DAYS),
            "global_default_ttl_days": BILI_SHARE_DEFAULT_TTL_DAYS}

@app.put("/api/share/config")
def put_share_config(req: dict, sid: str = Depends(current_identity)):
    if not sid:
        raise HTTPException(401, "需登录")
    days = req.get("default_ttl_days")
    try:
        days = int(days)
    except (TypeError, ValueError):
        raise HTTPException(400, "default_ttl_days 必须为整数（天）；0/-1 表示永久默认")
    if days < -1:
        raise HTTPException(400, "default_ttl_days 不能小于 -1")
    data = _load_shares()
    puc = data.setdefault("per_user_config", {})
    puc[sid] = {"default_ttl_days": days}
    _save_shares()
    return {"ok": True, "default_ttl_days": days}

@app.get("/api/share/list")
def share_list(sid: str = Depends(current_identity)):
    """owner 视角：列出本人全部分享令牌。"""
    if not sid:
        raise HTTPException(401, "需登录")
    data = _load_shares()
    items = []
    for tk, t in data.get("tokens", {}).items():
        if t.get("owner") != sid:
            continue
        items.append({
            "token": tk,
            "link": f"/share/{tk}",
            "resource_id": t.get("resource_id"),
            "title": t.get("title", ""),
            "created_at": t.get("created_at"),
            "expires_at": t.get("expires_at"),
            "ttl_label": "permanent" if t.get("ttl_days") in (None, "permanent") else t.get("ttl_days"),
            "revoked": t.get("revoked", False),
            "locked": t.get("locked", False),
            "access_count": t.get("access_count", 0),
        })
    items.sort(key=lambda x: x.get("created_at") or 0, reverse=True)
    return {"ok": True, "items": items}

@app.post("/api/share/purge")
def share_purge_dead(sid: str = Depends(current_identity)):
    """一键清理：删除本人所有已失效（已关闭 / 已过期）的分享记录。

    注意：本路由为字面量路径，须声明在 /api/share/{token} 之前（更具体者优先）。
    与「关闭共享」（软吊销，保留记录）不同：此操作把记录从 shares.json 彻底移除。
    """
    if not sid:
        raise HTTPException(401, "需登录")
    data = _load_shares()
    tokens = data.get("tokens", {})
    now = time.time()
    dead = []
    for tk, t in tokens.items():
        if t.get("owner") != sid:
            continue
        exp = t.get("expires_at")
        expired = exp is not None and exp < now
        if t.get("revoked") or expired:
            dead.append(tk)
    for tk in dead:
        tokens.pop(tk, None)
    if dead:
        _save_shares()
    return {"ok": True, "purged": len(dead)}

def _revoke_shares_for_resource(rid):
    """吊销 shares.json 中所有 resource_id==rid 的共享令牌（软吊销，保留记录）。"""
    if not rid:
        return
    data = _load_shares()
    toks = data.get("tokens", {})
    changed = False
    for tk, rec in toks.items():
        if (rec.get("resource_id") or "") == rid:
            if not rec.get("revoked") or not rec.get("locked"):
                rec["revoked"] = True
                rec["locked"] = True
                changed = True
    if changed:
        _save_shares()

def _owner_has_active_ref(owner, rid):
    """owner 本人在自身正常合集（排除 __trash__）中是否仍持有 rid 的活跃引用。"""
    if not owner or not rid:
        return False
    for c in _sid_collections(owner):
        if c.get("id") == "__trash__":
            continue
        if any((it.get("resource_id") or "") == rid for it in c.get("items", [])):
            return True
    return False

def _lock_owner_shares(owner, rid):
    """owner 删除自身引用后：吊销并锁定该 owner 签发的、绑定 rid 的全部令牌。

    锁定后无法重置开启（reactivate 会被拒），除非该 owner 将资源恢复到正常合集
    （_unlock_owner_shares）。与资源是否停在 admin 回收站无关——判据只看 owner 本人
    正常合集是否还持有 rid。
    """
    if not owner or not rid:
        return False
    with _shares_txn():
        data = _load_shares()
        changed = False
        for rec in data.get("tokens", {}).values():
            if rec.get("owner") == owner and (rec.get("resource_id") or "") == rid:
                if not rec.get("revoked") or not rec.get("locked"):
                    rec["revoked"] = True
                    rec["locked"] = True
                    changed = True
        if changed:
            _save_shares()
        return changed

def _unlock_owner_shares(owner, rid):
    """资源恢复到 owner 正常合集后：解除该 owner 对应令牌的锁定。

    令牌仍保持 revoked，需 owner 手动重新开启（reactivate）。
    """
    if not owner or not rid:
        return False
    with _shares_txn():
        data = _load_shares()
        changed = False
        for rec in data.get("tokens", {}).values():
            if rec.get("owner") == owner and (rec.get("resource_id") or "") == rid and rec.get("locked"):
                rec["locked"] = False
                changed = True
        if changed:
            _save_shares()
        return changed

class TrashPurgeReq(BaseModel):
    rid: str = ""
    body_key8: str = ""   # 指定则只清理该旧版本子目录，否则（rid 级）清理整个资源池目录

class TrashRestoreReq(BaseModel):
    rid: str = ""
    target_sid: str = ""
    body_key8: str = ""   # 指定则精确还原该旧版本，否则按 rid 级条目还原

class TrashBatchItem(BaseModel):
    rid: str = ""
    body_key8: str = ""

class TrashBatchReq(BaseModel):
    items: list[TrashBatchItem] = []

@app.get("/api/trash")
def trash_list(sid: str = Depends(current_identity)):
    """列出回收站资源（含物理存在性、当前活跃引用数）。仅管理员。"""
    if sid != "admin@local":
        raise HTTPException(403, "仅管理员可访问回收站")
    data = _load_collections()
    cols = data.get("admin@local", {}).get("collections", [])
    trash = next((c for c in cols if c.get("id") == "__trash__"), None)
    items = trash["items"] if trash else []
    out = []
    for it in items:
        r = it.get("resource_id")
        bk = it.get("body_key8") or ""
        if bk:
            phys = os.path.isdir(os.path.join(RESOURCES_DIR, r, bk))
        else:
            phys = os.path.isdir(os.path.join(RESOURCES_DIR, r)) if r else False
        # 精确活跃引用数：有 body_key8 时按 (rid, body_key8) 计，否则回退 rid 级
        active = _count_active_refs_body(r, bk) if bk else count_active_refs(r)
        out.append({**it, "physical_exists": phys, "active_refs": active})
    return {"ok": True, "items": out}

def _do_trash_purge(rid: str, bk: str) -> dict:
    """清理单条的核心逻辑（单条/批量共用）。rid 必填；bk 指定时只删该版本子目录。"""
    rid = (rid or "").strip()
    bk = (bk or "").strip()
    if not rid:
        raise HTTPException(400, "rid 必填")
    remove_trash_entry(rid, bk or None)  # 精确移除匹配的回收站条目（bk 缺省则移除该 rid 全部）
    # 物理清理：指定 body_key8 只删该旧版本子目录，否则（rid 级）删整个资源池目录。
    # 必须精确，否则会误删仍活跃的新版本内容。
    pd = os.path.join(RESOURCES_DIR, rid, bk) if bk else os.path.join(RESOURCES_DIR, rid)
    physical_removed = False
    if os.path.isdir(pd):
        shutil.rmtree(pd, ignore_errors=True)
        physical_removed = not os.path.isdir(pd)
    _revoke_shares_for_resource(rid)
    return {"ok": True, "rid": rid, "body_key8": bk, "physical_removed": physical_removed}

@app.post("/api/trash/purge")
def trash_purge(req: TrashPurgeReq, sid: str = Depends(current_identity)):
    """永久清理回收站资源：物理删除资源池目录 + 吊销同 rid 共享令牌。
    文章 .md 默认保留（A 立场），不无差别删除用户资产。仅管理员。"""
    if sid != "admin@local":
        raise HTTPException(403, "仅管理员可清理回收站")
    return _do_trash_purge((req.rid or "").strip(), (req.body_key8 or "").strip())

def _do_trash_restore(rid: str, bk: str, target_sid: str = "") -> str:
    """恢复单条的核心逻辑（单条/批量共用），返回目标 sid。"""
    rid = (rid or "").strip()
    bk = (bk or "").strip()
    if not rid:
        raise HTTPException(400, "rid 必填")
    with _collections_txn():
        data = _load_collections()
        cols = data.get("admin@local", {}).get("collections", [])
        trash = next((c for c in cols if c.get("id") == "__trash__"), None)
        # 精确匹配：指定 body_key8 还原该旧版本，否则按 rid 级条目还原。
        entry = next((it for it in (trash["items"] if trash else [])
                      if it.get("resource_id") == rid and (it.get("body_key8") or "") == bk), None)
        if not entry:
            raise HTTPException(404, "回收站中无此资源")
        tgt = (target_sid or "").strip() or entry.get("trashed_from") or "admin@local"
        tcols = _sid_collections(tgt)
        default = next((c for c in tcols if c.get("id") == "default"), None)
        if not default:
            raise HTTPException(400, "目标用户无默认合集")
        # 去重判据同上：目标合集里若已有同资源的 rel_path-only 条目，不再重复追加
        if not any(_rid_of_item(it) == rid for it in default["items"]):
            snap = entry.get("item_snapshot")
            # 有完整快照 → 逐字还原（cover/subtitle/vid/subtitle_source 等全字段），
            # 否则退回最小字段重建（兼容旧版无快照的回收站条目，仅保证可播放）
            new_item = dict(snap) if isinstance(snap, dict) else {}
            new_item["rel_path"] = new_item.get("rel_path") or entry.get("rel_path") or ("resources/" + rid + "/")
            new_item["title"] = new_item.get("title") or entry.get("title") or rid
            new_item["resource_id"] = rid
            new_item["restored_at"] = int(time.time())
            default["items"].append(new_item)
        if trash:
            trash["items"] = [it for it in trash["items"]
                              if not (it.get("resource_id") == rid and (it.get("body_key8") or "") == bk)]
        _save_collections()
    # 资源恢复到 owner 正常合集后，解除该 owner 对应令牌的锁定（令牌仍 revoked，需手动重新开启）
    _unlock_owner_shares(tgt, rid)
    return tgt

@app.post("/api/trash/restore")
def trash_restore(req: TrashRestoreReq, sid: str = Depends(current_identity)):
    """恢复回收站资源：重建一条引用挂回目标用户默认合集（默认 trashed_from，admin 可改派）。
    物理文件本就未删，恢复即重建逻辑引用。仅管理员。"""
    if sid != "admin@local":
        raise HTTPException(403, "仅管理员可恢复")
    rid = (req.rid or "").strip()
    tgt = _do_trash_restore(rid, (req.body_key8 or "").strip(), (req.target_sid or "").strip())
    return {"ok": True, "rid": rid, "target_sid": tgt}

def _trash_batch_result(req: TrashBatchReq, action: str) -> dict:
    """批量执行恢复/清理：逐条复用单条核心，单条失败不中断其余，返回明细。"""
    ok, failed = [], []
    fn = _do_trash_restore if action == "restore" else _do_trash_purge
    for item in req.items:
        rid, bk = (item.rid or "").strip(), (item.body_key8 or "").strip()
        entry = {"rid": rid, "body_key8": bk}
        try:
            r = fn(rid, bk)
            if action == "restore":
                entry["target_sid"] = r
            else:
                entry["physical_removed"] = r.get("physical_removed", False)
            ok.append(entry)
        except Exception as e:
            entry["error"] = str(e.detail) if isinstance(e, HTTPException) else str(e)
            failed.append(entry)
    return {"ok": True, "action": action, "total": len(req.items),
            "succeeded": len(ok), "failed_count": len(failed),
            "results": ok, "failures": failed}

@app.post("/api/trash/restore-batch")
def trash_restore_batch(req: TrashBatchReq, sid: str = Depends(current_identity)):
    """批量恢复：逐条重建引用（每条独立事务，单条失败不影响其余）。仅管理员。"""
    if sid != "admin@local":
        raise HTTPException(403, "仅管理员可恢复")
    return _trash_batch_result(req, "restore")

@app.post("/api/trash/purge-batch")
def trash_purge_batch(req: TrashBatchReq, sid: str = Depends(current_identity)):
    """批量清理：逐条精确清理（bk 指定则只删该版本，不碰当前版）。仅管理员。"""
    if sid != "admin@local":
        raise HTTPException(403, "仅管理员可清理回收站")
    return _trash_batch_result(req, "purge")

@app.get("/share/{token}", include_in_schema=False)
def share_page(token: str):
    """只读分享页入口：返回单页前端，由前端按 location.pathname 进入 share-mode。

    必须作为真实路由存在：run_server.py 以 StaticFiles(html=True) 挂在 "/"，
    对 /share/<token> 这类不存在于磁盘的路径会直接 404，前端根本没机会执行。
    app.py 内的路由先于该 mount 注册，故优先命中这里。
    """
    return FileResponse(os.path.join(BASE, "index.html"), media_type="text/html")


@app.get("/api/share/{token}")
def share_info(token: str, sid: str = Depends(current_identity)):
    """分享页拉取资源元数据（标题/文件清单/是否过期）。需登录。"""
    if not sid:
        raise HTTPException(403, "需登录后访问")
    tok = _resolve_share(token)
    if not tok:
        raise HTTPException(404, "分享链接无效或已失效")
    owner = tok.get("owner")
    rid = tok.get("resource_id")
    item, paths = _find_resource(owner, rid)
    data = _load_shares()
    if token in data.get("tokens", {}):
        data["tokens"][token]["access_count"] = data["tokens"][token].get("access_count", 0) + 1
        _save_shares()
    # 关联 AI 文章：按视频束 subtitle 反查 .md，纳入分享页下载入口
    article_rel = None
    article_filename = None
    if rid:
        _arts = _article_rels_for_resource(rid, (item or {}).get("body_key8"), owner)
        if _arts:
            article_rel = _arts[0]
            article_filename = os.path.basename(article_rel)
    return {
        "ok": True,
        "token": token,
        "owner": owner,
        "title": (item or {}).get("title", tok.get("title", "")),
        "resource_id": rid,
        "rel_path": tok.get("rel_path"),
        "subtitle": (item or {}).get("subtitle", ""),
        "subtitle_srt": ((item or {}).get("subtitle_srt") or _subtitle_srt_rel((item or {}).get("subtitle", ""))),
        "subtitle_source": (item or {}).get("subtitle_source", ""),
        "cover": (item or {}).get("cover", ""),
        # 发布日期 / 内容子类型（2026-11-23）：分享页元数据也回显，供被共享方卡片显示/筛选。
        "published_at": (item or {}).get("published_at", ""),
        "content_type": (item or {}).get("content_type", ""),
        "article_rel": article_rel,
        "article_filename": article_filename,
        "article_bold": (_article_bold_for(
            owner, os.path.splitext(os.path.basename(article_rel))[0],
            (item or {}).get("subtitle")) if article_rel else None),
        "expires_at": tok.get("expires_at"),
        "ttl_label": "permanent" if tok.get("ttl_days") in (None, "permanent") else tok.get("ttl_days"),
        "is_owner": owner == sid,
        "accepted": token in ((data.get("accepted") or {}).get(sid) or {}),
    }

@app.put("/api/share/reset")
def share_reset(req: dict, sid: str = Depends(current_identity)):
    """重设某令牌有效期。

    - 传 ttl_option 时：按用户指定的新期限重算（沿用原期限/自定义天数/永久），
      并同步更新 tok["ttl_days"]，使后续「重设」默认沿用新期限。
    - 不传 ttl_option 时：兼容旧行为，按原 ttl_days 从当前时刻重算（续期）。
    """
    if not sid:
        raise HTTPException(401, "需登录")
    token = req.get("token")
    ttl_option = req.get("ttl_option")
    data = _load_shares()
    tok = data.get("tokens", {}).get(token)
    if not tok or tok.get("owner") != sid:
        raise HTTPException(404, "令牌不存在或不属于你")
    if tok.get("revoked"):
        raise HTTPException(400, "令牌已吊销")
    old_ttl = tok.get("ttl_days")
    if ttl_option is not None and str(ttl_option).strip() != "":
        # 用户指定了新期限（沿用原期限会传原天数；自定义传数字；永久传 permanent）
        expires_at, ttl_label = _compute_expires_at(ttl_option, sid)
        tok["expires_at"] = expires_at
        tok["ttl_days"] = None if ttl_label == "permanent" else ttl_label
    else:
        # 兼容旧行为：按原 ttl_days 从当前时刻重新起算
        if old_ttl in (None, "permanent"):
            tok["expires_at"] = None
        else:
            try:
                days = int(old_ttl)
            except (TypeError, ValueError):
                days = BILI_SHARE_DEFAULT_TTL_DAYS
            tok["expires_at"] = None if days in (0, -1) else time.time() + days * 86400
    _save_shares()
    return {"ok": True, "expires_at": tok["expires_at"], "ttl_label": "permanent" if tok.get("ttl_days") in (None, "permanent") else tok.get("ttl_days")}

@app.post("/api/share/{token}/reactivate")
def share_reactivate(token: str, sid: str = Depends(current_identity)):
    """重新开启已吊销（关闭）的共享：revoked 置 False，并按原 ttl_days 从当前时刻续期。

    区别于「重设期限」（reset 对已吊销令牌直接 400）：此端点专门把失效链接救活。
    幂等：令牌本就有效时返回 already_active=True，不改动有效期。
    注意：本路由含 /reactivate 后缀（两段路径），不会与 /api/share/{token} 单段路由冲突。
    """
    if not sid:
        raise HTTPException(401, "需登录")
    data = _load_shares()
    tok = data.get("tokens", {}).get(token)
    if not tok or tok.get("owner") != sid:
        raise HTTPException(404, "令牌不存在或不属于你")
    if tok.get("locked"):
        raise HTTPException(409, "共享链接已锁定：请先将对应资源恢复到正常合集目录后再开启")
    if not _owner_has_active_ref(tok.get("owner"), tok.get("resource_id")):
        raise HTTPException(409, "共享链接已失效：发布者已无该资源的正常合集引用")
    if not tok.get("revoked"):
        return {"ok": True, "already_active": True,
                "expires_at": tok.get("expires_at"),
                "ttl_label": "permanent" if tok.get("ttl_days") in (None, "permanent") else tok.get("ttl_days")}
    old_ttl = tok.get("ttl_days")
    if old_ttl in (None, "permanent"):
        tok["expires_at"] = None
    else:
        try:
            days = int(old_ttl)
        except (TypeError, ValueError):
            days = BILI_SHARE_DEFAULT_TTL_DAYS
        tok["expires_at"] = None if days in (0, -1) else time.time() + days * 86400
    tok["revoked"] = False
    _save_shares()
    return {"ok": True, "expires_at": tok["expires_at"],
            "ttl_label": "permanent" if tok.get("ttl_days") in (None, "permanent") else tok.get("ttl_days")}

@app.delete("/api/share/{token}")
def share_revoke(token: str, sid: str = Depends(current_identity)):
    """吊销（关闭共享）。仅 owner 可吊销自己的令牌。"""
    if not sid:
        raise HTTPException(401, "需登录")
    data = _load_shares()
    tok = data.get("tokens", {}).get(token)
    if not tok or tok.get("owner") != sid:
        raise HTTPException(404, "令牌不存在或不属于你")
    tok["revoked"] = True
    _save_shares()
    return {"ok": True}

@app.delete("/api/share/{token}/purge")
def share_purge(token: str, sid: str = Depends(current_identity)):
    """彻底删除一条分享记录（仅 owner）。

    区别于「关闭共享」（软吊销，记录保留）：此操作把令牌从 shares.json 移除，
    记录不再出现在「我的共享」列表中；接收方侧会转为 missing（灰显，可自行清理）。
    """
    if not sid:
        raise HTTPException(401, "需登录")
    data = _load_shares()
    tok = data.get("tokens", {}).get(token)
    if not tok or tok.get("owner") != sid:
        raise HTTPException(404, "令牌不存在或不属于你")
    data["tokens"].pop(token, None)
    _save_shares()
    return {"ok": True, "removed": token}

class ShareAcceptReq(BaseModel):
    accept: bool = True

@app.post("/api/share/accepted/prune")
def share_accepted_prune(sid: str = Depends(current_identity)):
    """清理「被共享」中已失效（过期 / 被吊销 / 令牌已删除）的条目。

    只删接收方自己的登记，不触碰 owner 的文件与令牌。
    注意：本路由必须声明在 /api/share/{token}/accept 之前（更具体者优先）。
    """
    if not sid:
        raise HTTPException(401, "需登录")
    data = _load_shares()
    accepted = data.get("accepted") or {}
    mine = accepted.get(sid) or {}
    tokens = data.get("tokens") or {}
    now = time.time()
    removed = []
    for token in list(mine.keys()):
        tok = tokens.get(token)
        dead = (tok is None) or bool(tok.get("revoked")) or (
            tok.get("expires_at") is not None and tok["expires_at"] < now)
        if dead:
            mine.pop(token, None)
            removed.append(token)
    if removed:
        if mine:
            accepted[sid] = mine
        else:
            accepted.pop(sid, None)
        data["accepted"] = accepted
        _save_shares()
    return {"ok": True, "removed": len(removed)}

@app.post("/api/share/{token}/accept")
def share_accept(token: str, req: ShareAcceptReq, sid: str = Depends(current_identity)):
    """把分享令牌登记进「我的媒体库 → 📥 被共享」，或移出（accept=false）。

    仅登记一份引用关系：不复制文件、不改动 owner 侧任何数据。
    owner 本人调用会被拒（自己的资源无需加入被共享）。
    """
    if not sid:
        raise HTTPException(401, "需登录")
    if req.accept:
        tok = _resolve_share(token)
        if not tok:
            raise HTTPException(404, "分享链接无效或已失效")
        if tok.get("owner") == sid:
            raise HTTPException(400, "这是你自己的资源，无需加入「被共享」")
    data = _load_shares()
    accepted = data.setdefault("accepted", {})
    mine = accepted.setdefault(sid, {})
    if req.accept:
        prev = mine.get(token) or {}
        # 重复点击「加入」不刷新 added_at，避免列表排序跳动
        mine[token] = {"added_at": prev.get("added_at") or time.time()}
    else:
        mine.pop(token, None)
        if not mine:
            accepted.pop(sid, None)   # 空桶不落库
    _save_shares()
    return {"ok": True, "accepted": bool(req.accept), "total": len(mine)}

@app.get("/api/library")
def library(sid: str = Depends(current_identity)):
    """返回当前用户（优先网关注入的 X-User-Email 真实身份，退回 X-Session-Id）的全部合集及条目；stale 标记文件是否已失效。"""
    cols = _sid_collections(sid)
    out = []
    healed = False
    for c in cols:
        items = []
        for it in c.get("items", []):
            rel = it.get("rel_path", "")
            # 自愈：文件已被外部删除/搬迁时，改指同一视频仍然存在的其它副本
            if (not rel) or (not os.path.isfile(os.path.join(DOWNLOADS, rel))):
                _alt = _find_existing_copy(rel, it.get("vid", ""), it.get("title", ""))
                if _alt:
                    it["rel_path"] = _alt
                    _stem = os.path.basename(_alt).rsplit(".", 1)[0]
                    try:
                        _sib = set(os.listdir(os.path.join(DOWNLOADS, os.path.dirname(_alt))))
                    except OSError:
                        _sib = set()
                    _sub = match_subtitle(_stem, _sib)
                    it["subtitle"] = (os.path.dirname(_alt) + "/" + _sub) if _sub else ""
                    rel = _alt
                    healed = True
            items.append({
                **it,
                "subtitle_srt": (it.get("subtitle_srt") or _subtitle_srt_rel(it.get("subtitle"))),
                "stale": (not rel) or (not os.path.isfile(os.path.join(DOWNLOADS, rel))),
            })
        out.append({"id": c["id"], "name": c.get("name", c["id"]), "shared": False, "items": items})
    if healed:
        _save_collections()
    # 「被共享」虚拟合集（接收方主动加入的他人共享）：实时 join 令牌状态，不落 collections.json
    shared = _shared_with_me_collection(sid)
    if shared:
        out.append(shared)
    is_admin = sid == normalize_identity(ADMIN_USER)
    trash_count = 0
    if is_admin:
        _td = _load_collections().get("admin@local", {}).get("collections", [])
        _tt = next((c for c in _td if c.get("id") == "__trash__"), None)
        trash_count = len(_tt["items"]) if _tt else 0
    return {"collections": out, "is_admin": is_admin, "trash_count": trash_count}

@app.post("/api/collection")
def create_collection(req: CollectionReq, sid: str = Depends(current_identity)):
    cols = _sid_collections(sid)
    name = (req.name or "").strip() or "新建合集"
    if any(c["name"] == name for c in cols):
        raise HTTPException(400, "已存在同名合集")
    cid = "c" + uuid.uuid4().hex[:10]
    cols.append({"id": cid, "name": name, "items": []})
    _save_collections()
    return {"ok": True, "id": cid, "name": name}

@app.put("/api/collection/{cid}")
def rename_collection(cid: str, req: CollectionReq, sid: str = Depends(current_identity)):
    cols = _sid_collections(sid)
    c = next((x for x in cols if x["id"] == cid), None)
    if not c:
        raise HTTPException(404, "合集不存在")
    name = (req.name or "").strip()
    if not name:
        raise HTTPException(400, "名称不能为空")
    if any(x["name"] == name for x in cols):
        raise HTTPException(400, "已存在同名合集")
    c["name"] = name
    _save_collections()
    return {"ok": True}

@app.delete("/api/collection/{cid}")
def delete_collection(cid: str, sid: str = Depends(current_identity)):
    if cid == "default":
        raise HTTPException(400, "默认合集不可删除")
    cols = _sid_collections(sid)
    c = next((x for x in cols if x["id"] == cid), None)
    if not c:
        raise HTTPException(404, "合集不存在")
    # 删除合集时，把其中的视频整体移入「默认合集」（字幕随视频一起，不删文件）
    default = next((x for x in cols if x["id"] == "default"), None)
    moved = 0
    if default is not None:
        existing = {it.get("rel_path") for it in default["items"]}
        for it in c.get("items", []):
            rel = it.get("rel_path")
            if rel and rel not in existing:
                default["items"].append(it)
                existing.add(rel)
                moved += 1
    cols[:] = [x for x in cols if x["id"] != cid]
    _save_collections()
    return {"ok": True, "moved_to_default": moved}

@app.post("/api/collection/{cid}/items")
def add_collection_item(cid: str, req: CollectionItemReq, sid: str = Depends(current_identity)):
    cols = _sid_collections(sid)
    c = next((x for x in cols if x["id"] == cid), None)
    if not c:
        raise HTTPException(404, "合集不存在")
    rel = (req.rel_path or "").strip()
    if not rel:
        raise HTTPException(400, "rel_path 不能为空")
    entry = {
        "rel_path": rel,
        "title": (req.title or _title_from_filename(os.path.basename(rel))),
        "vid": req.vid or "",
        "duration": req.duration,
        "cover": req.cover or "",
        "subtitle": req.subtitle or "",
        "added_at": time.time(),
    }
    for it in c["items"]:
        if it.get("rel_path") == rel:
            for k, v in entry.items():
                if v not in (None, ""):
                    it[k] = v
            _save_collections()
            return {"ok": True, "updated": True}
    c["items"].append(entry)
    _save_collections()
    return {"ok": True, "updated": False}

@app.delete("/api/collection/{cid}/items")
def remove_collection_item(cid: str, req: CollectionItemReq, sid: str = Depends(current_identity)):
    """合集条目级删除（公开 API，供采集器/脚本/集成调用；前端不调，UI 走 /api/files/delete）。

    ⚠️ 「引用归零」语义必须与 delete_files 一致：摘掉引用后，若该 rid 已无任何活跃引用
    → 入 admin 回收站（带完整快照，可恢复）；若本人已无活跃引用 → 锁定本人分享令牌。
    此前这里只做列表过滤，导致同一个用户动作两条路径两种结果：从 UI 删是「进回收站可恢复」，
    从接口删是「凭空消失、资源留在磁盘无人管、分享链接继续有效」。
    """
    with _collections_txn():   # 与 delete_files 一致：摘引用 → 归零判定 → 入回收站/锁令牌 原子化
        cols = _sid_collections(sid)
        c = next((x for x in cols if x["id"] == cid), None)
        if not c:
            raise HTTPException(404, "合集不存在")
        rel_norm = (req.rel_path or "").replace("\\", "/").strip()
        before = len(c["items"])
        hit = next((it for it in c["items"]
                    if (it.get("rel_path") or "").replace("\\", "/") == rel_norm), None)
        c["items"] = [it for it in c["items"]
                      if (it.get("rel_path") or "").replace("\\", "/") != rel_norm]
        removed = before - len(c["items"])

        # 资源池条目：rid 以路径为准（物理目录才是真相），条目字段仅作兜底
        if hit and rel_norm.startswith("resources/"):
            _parts = rel_norm.split("/")
            rid = (_parts[1] if len(_parts) > 1 else "") or _rid_of_item(hit)
            if rid:
                # 判定一：全局已无活跃引用 → 入回收站。必须传 item=hit 完整快照，
                # 否则 restore 时封面/字幕/日期/类型全丢（见 ensure_trash_entry docstring）。
                if count_active_refs(rid) == 0:
                    ensure_trash_entry(rid, hit.get("title") or rel_norm, sid, rel_norm, item=hit)
                # 判定二：本人是否还有活跃引用 → 锁令牌。**独立于判定一**：
                # 资源被其他 owner 也引用时（全局计数 > 0）本人令牌照样要锁，
                # 否则删完自己的引用后分享链接仍然有效。
                still_has = any(
                    c2.get("id") != "__trash__" and any(
                        _rid_of_item(it2) == rid for it2 in c2.get("items", [])
                    )
                    for c2 in cols
                )
                if not still_has:
                    _lock_owner_shares(sid, rid)

        _save_collections()
        # found 便于调用方区分「本来就不在」与「删过了」；老调用方只看 ok 不受影响
        return {"ok": True, "removed": removed, "found": hit is not None}

@app.post("/api/collection/{cid}/items/move")
def move_items(cid: str, req: MoveItemsReq, sid: str = Depends(current_identity)):
    """把源合集(cid)中的若干视频（按 rel_path）整体移动到目标合集(target_cid)。
    字幕随视频条目一起移动；目标合集已存在的同名视频不会重复。"""
    cols = _sid_collections(sid)
    src = next((x for x in cols if x["id"] == cid), None)
    tgt = next((x for x in cols if x["id"] == req.target_cid), None)
    if not src:
        raise HTTPException(404, "源合集不存在")
    if not tgt:
        raise HTTPException(404, "目标合集不存在")
    rels = [r for r in (req.rel_paths or []) if str(r).strip()]
    if not rels:
        raise HTTPException(400, "未选择要移动的视频")
    moved = 0
    existing = {it.get("rel_path") for it in tgt["items"]}
    for it in list(src["items"]):
        rel = it.get("rel_path")
        if rel in rels:
            src["items"].remove(it)
            if rel not in existing:
                tgt["items"].append(it)
                existing.add(rel)
            moved += 1
    _save_collections()
    return {"ok": True, "moved": moved}

def _prune_orphan_dirs(dirs, sid=None):
    """清理已无媒体文件的任务目录（连带封面 / 孤立字幕 / 目录骨架）。

    仅当目录内不再残留任何主文件（MEDIA_EXT 媒体 / OFFICE_EXT 文档）时才整目录删除，
    避免误删同批次其它分P。严格限制在用户自己的根目录内。
    """
    pruned = []
    root = os.path.abspath(user_root(sid))
    for d in (dirs or []):
        try:
            d = os.path.abspath(d)
        except Exception:
            continue
        if not d.startswith(root + os.sep) or d == root:
            continue                      # 越界或用户根本身，跳过
        if not os.path.isdir(d):
            continue
        try:
            remain_media = any(
                fn.lower().endswith(MAIN_EXT)
                for fn in os.listdir(d)
                if os.path.isfile(os.path.join(d, fn))
            )
        except Exception:
            continue
        if remain_media:
            continue                      # 还有视频，保留整个目录
        try:
            shutil.rmtree(d)
            pruned.append(os.path.relpath(d, DOWNLOADS))
        except Exception:
            pass
    return pruned

@app.post("/api/files/delete")
def delete_files(req: DeleteFilesReq, sid: str = Depends(current_identity)):
    """批量删除视频文件（及其绑定的字幕文件），并从该用户所有合集中移除引用。
    items: [{"rel_path":..., "subtitle":...}]，字幕随视频整体删除。
    删除后若任务目录已无媒体文件，会整目录清理（含封面、孤立字幕、目录骨架）。"""
    with _collections_txn():  # O7 并发安全：整段「移除引用→引用归零入回收站→锁定共享」原子化
        cols = _sid_collections(sid)
        deleted, missing, trashed = [], [], []
        touched_dirs = []
        own_prefix = "users/" + user_hash(sid) + "/"
        for ent in (req.items or []):
            # 每轮重新取 cols：循环体内 ensure_trash_entry 会保存并可能触发缓存重载，
            # 之后旧的 cols 就与 _collections_cache 脱钩 —— 后续条目会"删了个寂寞"
            # （批量删除只生效第一条的根因）。
            cols = _sid_collections(sid)
            rel = (ent.get("rel_path") if isinstance(ent, dict) else str(ent)).strip()
            sub = (ent.get("subtitle", "") if isinstance(ent, dict) else "").strip()
            if not rel:
                continue
            rel_norm = rel.replace("\\", "/").strip()
            is_resource = rel_norm.startswith("resources/")
            # 资源池条目的 rid 与展示标题（用于回收站记录）
            rid = None
            title = rel_norm
            matched_item = None            # 命中的合集条目（完整快照，供回收站 restore 还原全字段）
            if is_resource:
                parts = rel_norm.split("/")
                rid = parts[1] if len(parts) > 1 else None
                for c in cols:
                    for it in c["items"]:
                        if (it.get("rel_path") or "").replace("\\", "/") == rel_norm:
                            title = it.get("title") or title
                            rid = rid or it.get("resource_id")
                            matched_item = it
                            break
            if is_resource:
                pass  # 资源池物理文件为共享存储，不删；仅移除引用，引用归零后入回收站
            elif not rel_norm.startswith(own_prefix):
                # 安全：仅允许删除本人 users/{hash}/ 下的文件，杜绝跨用户删他人资源
                missing.append(rel_norm)
                continue
            else:
                vpath = os.path.join(DOWNLOADS, rel_norm)
                if os.path.isfile(vpath):
                    touched_dirs.append(os.path.dirname(vpath))
                    try:
                        os.remove(vpath); deleted.append(rel_norm)
                    except Exception:
                        pass
                else:
                    missing.append(rel_norm)
            if sub and rel_norm.startswith(own_prefix):
                spath = os.path.join(DOWNLOADS, sub)
                if os.path.isfile(spath):
                    touched_dirs.append(os.path.dirname(spath))
                    try:
                        os.remove(spath); deleted.append(sub)
                    except Exception:
                        pass
            for c in cols:
                c["items"] = [it for it in c["items"] if (it.get("rel_path") or "").replace("\\", "/") != rel_norm]
            # 资源池引用归零 → 入回收站（物理保留，由 admin 决定是否清理）
            if is_resource and rid:
                if count_active_refs(rid) == 0:
                    ensure_trash_entry(rid, title, sid, rel_norm, item=matched_item)
                    trashed.append(rid)
                # per-user 共享令牌加锁：删除者若自身已无 rid 活跃引用 → 其签发的共享令牌失效且不可重置
                # （与资源是否停在 admin 回收站无关；判定只看 owner 本人正常合集是否还持有 rid）
                still_has = any(
                    c.get("id") != "__trash__" and any(
                        _rid_of_item(it) == rid for it in c.get("items", [])
                    )
                    for c in cols
                )
                if not still_has:
                    _lock_owner_shares(sid, rid)
        _save_collections()
        pruned = _prune_orphan_dirs(set(touched_dirs), sid)
        return {"ok": True, "deleted": deleted, "missing": missing, "pruned_dirs": pruned, "trashed_resources": trashed}

@app.post("/api/upload")
async def upload_files(
    cid: str = Form("default"),
    files: list[UploadFile] = File(...),
    sid: str = Depends(current_identity),
):
    """从浏览器上传本地视频（及其字幕），按「内容哈希 rid + 内容派生 body_key8」直接入资源池；
    走 _add_to_collection 登记合集引用，删除引用归零即入 __trash__（与资源池条目同保护）。
    见 RM-实施指引 §2.2。内容级去重由 _ingest_into_pool 保证（同内容只存一份）。"""
    videos, subs, covers, metas, offices = [], [], [], [], []
    for f in files:
        ext = os.path.splitext(f.filename or "")[1].lower()
        if ext in MEDIA_EXT:
            videos.append(f)
        elif ext in OFFICE_EXT:
            # office 文档是独立主资源（不参与视频字幕主干配对），与视频同链路各自入池
            offices.append(f)
        elif ext in SUB_EXTS:
            subs.append(f)
        elif ext in IMG_EXTS:
            covers.append(f)
        elif ext in META_EXT:
            metas.append(f)
        # 其它类型静默忽略（仅处理媒体 / 文档 / 字幕 / 封面 / meta）

    # 暂存到用户级 staging，再由 _ingest_into_pool 迁入资源池（staging 会被消费）
    stage_dir = os.path.join(user_root(sid), "_staging")
    os.makedirs(stage_dir, exist_ok=True)
    saved_videos = {}  # stem -> (abs_path, filename, rid, body_key8, content_sha256)
    for f in videos:
        try:
            data = await f.read()
        except Exception:
            continue
        h = hashlib.sha256(data).hexdigest()
        rid = "r" + h[:15]
        body_key8 = _body_key8_from_hash(h)
        safe = _safe_upload_name(f.filename)
        dest = _uniq_path(os.path.join(stage_dir, safe))
        with open(dest, "wb") as w:
            w.write(data)
        saved_videos[os.path.splitext(safe)[0]] = (dest, f.filename, rid, body_key8, h)

    async def _stage_bucket(lst):
        out = {}
        for f in lst:
            try:
                data = await f.read()
            except Exception:
                continue
            safe = _safe_upload_name(f.filename)
            dest = _uniq_path(os.path.join(stage_dir, safe))
            with open(dest, "wb") as w:
                w.write(data)
            out[os.path.basename(dest)] = dest
        return out

    saved_subs = await _stage_bucket(subs)
    saved_covers = await _stage_bucket(covers)
    saved_metas = await _stage_bucket(metas)

    # 把「同视频主干」的字幕 / 封面 / meta 配对到各自视频（缺陷①：收集全部字幕，不只一个）
    consumed_sub, consumed_cover, consumed_meta = set(), set(), set()
    added = 0
    for stem, (dest, fname, rid, body_key8, content_sha256) in saved_videos.items():
        matched = _match_siblings_by_stem(stem, saved_subs, consumed_sub)
        matched += _match_siblings_by_stem(stem, saved_covers, consumed_cover)
        matched += _match_siblings_by_stem(stem, saved_metas, consumed_meta)
        try:
            _ingest_into_pool(sid, rid, body_key8, dest, matched,
                              _title_from_filename(fname), target_cid=cid,
                              content_sha256=content_sha256)
            added += 1
            # 视频入池后，把此前先到、暂存于 pending 的字幕 / 封面 / meta 补挂进来
            _flush_pending_attach(sid, rid, body_key8, stem)
        except HTTPException:
            pass

    # ONLYOFFICE 文档：各自按内容哈希派生 rid，独立入池（不配对字幕/封面）
    for f in offices:
        try:
            data = await f.read()
        except Exception:
            continue
        h = hashlib.sha256(data).hexdigest()
        rid = "r" + h[:15]
        body_key8 = _body_key8_from_hash(h)
        safe = _safe_upload_name(f.filename)
        dest = _uniq_path(os.path.join(stage_dir, safe))
        with open(dest, "wb") as w:
            w.write(data)
        try:
            _ingest_into_pool(sid, rid, body_key8, dest, [],
                              _title_from_filename(f.filename), target_cid=cid,
                              content_sha256=h, source_type="office")
            added += 1
        except HTTPException:
            pass

    # 未被任何视频配对的字幕 / 封面 / meta → 挂到「已存在的同名资源」，否则进 pending 兜底
    attached = 0
    pending = 0
    for name, path in saved_subs.items():
        if name in consumed_sub:
            continue
        if _attach_siblings_to_existing(sid, name, [path], [], [], cid):
            attached += 1
        else:
            _stage_pending_attach(sid, name, path)
            pending += 1
    for name, path in saved_covers.items():
        if name in consumed_cover:
            continue
        if _attach_siblings_to_existing(sid, name, [], [path], [], cid):
            attached += 1
        else:
            _stage_pending_attach(sid, name, path)
            pending += 1
    for name, path in saved_metas.items():
        if name in consumed_meta:
            continue
        if _attach_siblings_to_existing(sid, name, [], [], [path], cid):
            attached += 1
        else:
            _stage_pending_attach(sid, name, path)
            pending += 1

    # skipped：真正被忽略的文件 = 总数 - 视频(新增) - 已补挂 - 待补挂 - 已作为附加物并入视频的同源文件
    consumed = len(consumed_sub) + len(consumed_cover) + len(consumed_meta)
    skipped = len(files) - added - attached - pending - consumed
    return {"ok": True, "added": added, "attached": attached,
            "pending": pending, "skipped": max(skipped, 0), "total": len(files)}


# ==================== 图文生产闭环：图片资产（用户隔离）====================
# 开源部署无采集端 → 图文靠前端写入；图片作为独立资产，用户隔离、按需引用、
# 未使用者由用户手动移入回收站。设计见 wechat-archive/docs/公众号图文富样式-治本方案.md §8。
IMAGE_RE = re.compile(r"/api/image/([A-Za-z0-9_-]+)")   # 文章正文里的图片引用

def _image_root(sid):
    return os.path.join(user_root(sid), "images")

def _image_index_path(sid):
    return os.path.join(_image_root(sid), "index.json")

def _load_image_index(sid):
    p = _image_index_path(sid)
    try:
        with open(p, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}

def _save_image_index(sid, data):
    root = _image_root(sid)
    os.makedirs(root, exist_ok=True)
    p = _image_index_path(sid)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, p)

def _article_used_image_ids(sid):
    """扫描【本人】文章正文，返回本人文章引用的图片 id 集合。
    引用天然按 owner：编辑器只插本人上传的图（/api/image/<id> 无 share），
    共享文章的图只读、不写回自己的文章。故 used 判定必须按人隔离，
    否则两个用户上传同内容图（内容哈希 → 同 id）会互相卡住删除。
    按需全量重算（单用户图片/文章量级小），不做增量引用表以避免双写一致性。"""
    used = set()
    data = _load_collections()
    mine = data.get(sid, {})
    for c in mine.get("collections", []):
        for it in c.get("items", []):
            if it.get("media_type") != "article" and it.get("source_type") != "wechat_article":
                continue
            rel = (it.get("rel_path") or "").replace("\\", "/")
            if not rel:
                continue
            ap = os.path.join(DOWNLOADS, rel)
            if not os.path.isfile(ap):
                continue
            try:
                with open(ap, encoding="utf-8", errors="ignore") as f:
                    used.update(IMAGE_RE.findall(f.read()))
            except Exception:
                pass
    return used

def _image_put_bytes(sid, idx, data, ext, name):
    """把一份图片字节写入本人资产区，内容寻址去重（iid = "i"+sha256(内容)[:15]）。

    image_upload（前端上传）与 article_images_import（服务端从文章取图）共用此函数，
    保证两条路的落盘 / 去重 / index 语义完全一致。
    返回 (iid, dedup, restored)：
      dedup=True    库里已有同内容图，本次未重复落盘；
      restored=True 该图此前在回收站，本次被重新激活（另存语义 = 我要用它）。"""
    h = hashlib.sha256(data).hexdigest()
    iid = "i" + h[:15]
    root = _image_root(sid)
    os.makedirs(root, exist_ok=True)
    dest = os.path.join(root, iid + ext)
    dedup = iid in idx and os.path.isfile(dest)
    restored = False
    if not dedup:
        with open(dest, "wb") as w:
            w.write(data)
        idx[iid] = {"ext": ext, "name": _safe_upload_name(name or (iid + ext)),
                    "size": len(data), "added_at": int(time.time()), "trashed": False}
    elif (idx.get(iid) or {}).get("trashed"):
        idx[iid]["trashed"] = False
        restored = True
    return iid, dedup, restored

@app.post("/api/image/upload")
async def image_upload(files: list[UploadFile] = File(...), sid: str = Depends(current_identity)):
    """上传图片到本人隔离区 users/<hash>/images/，按内容哈希 id 去重。
    返回 [{id, url, name, size, dedup, restored}]；前端拿到 url 写进富文本 <img src>。"""
    os.makedirs(_image_root(sid), exist_ok=True)
    idx = _load_image_index(sid)
    out = []
    for f in files:
        ext = os.path.splitext(f.filename or "")[1].lower()
        if ext not in IMG_EXTS:
            continue
        try:
            data = await f.read()
        except Exception:
            continue
        iid, dedup, restored = _image_put_bytes(sid, idx, data, ext, f.filename or "")
        meta = idx.get(iid) or {}
        out.append({"id": iid, "url": "/api/image/" + iid,
                    "name": meta.get("name", iid), "size": meta.get("size", len(data)),
                    "dedup": dedup, "restored": restored})
    _save_image_index(sid, idx)
    return {"ok": True, "items": out}

# ---------- 文章图片入库（服务端取图，前端只发 rel_path）----------
# 为什么放服务端：被入库的图本来就在资源池里（resources/<rid>/<bk8>/），
# 前端取图只能 blob → base64 → POST 回同一台机器，白跑两遍带宽还要过网关；
# 服务端直接读文件算 sha256 走 _image_put_bytes 即可。
ARTICLE_IMG_MAX_BYTES = 20 * 1024 * 1024    # 单张上限，防超大图拖垮请求
ARTICLE_IMG_MAX_PER_ARTICLE = 300           # 单篇上限，防异常 HTML 塞暴列表

class _ImgSrcCollector(HTMLParser):
    """只收 <img src>，不做清洗——入库要的是原始引用。"""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.srcs = []
    def handle_starttag(self, tag, attrs):
        if tag.lower() != "img":
            return
        for k, v in attrs:
            if k.lower() == "src":
                if v:
                    self.srcs.append(v.strip())
                break

def _article_img_srcs(html_text):
    p = _ImgSrcCollector()
    try:
        p.feed(html_text or "")
    except Exception:
        pass
    return p.srcs

def _resolve_pool_image(rel_html, src):
    """把文章里的 <img src> 解析成池内绝对路径。
    非池内引用（data:/http:/api/image/ 已有资产）返回 ""——本函数只负责「本地文件」这一类。"""
    s = (src or "").strip()
    if not s or s.startswith("data:") or s.startswith("//"):
        return ""
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", s):   # http: https: ftp: 等外链
        return ""
    if s.startswith("/"):                            # /api/image/<id> 或站内绝对路径
        return ""
    s = urllib.parse.unquote(s)
    base = os.path.join(DOWNLOADS, rel_html)
    ap = os.path.abspath(os.path.join(os.path.dirname(base), s))
    root = os.path.abspath(DOWNLOADS)
    if not ap.startswith(root + os.sep) or not os.path.isfile(ap):
        return ""
    return ap

class ArticleImagesImportReq(BaseModel):
    rel_paths: list[str] = []

@app.post("/api/article/images/import")
def article_images_import(req: ArticleImagesImportReq, sid: str = Depends(current_identity)):
    """把选中图文的「正文图片 + 封面」复制成本人的图片资产（幂等）。

    语义边界（2026-11-24）：
      - 只处理【本人】条目；不属你 / 非图文 / 正文缺失 → 该条 skipped 回报，不整批失败。
      - 正文取池内相对引用的图；`/api/image/<id>` 说明本来就是资产，计入 already_asset 跳过。
      - 封面（images[] 里主干为 cover 的那张）一并入库——采集端把它单独存成 cover.jpg，
        不在正文 <img> 里，不特意处理就永远收不到。
      - 入库是「复制一份资产」：文章正文仍引用自己目录里的图，删资产不会让文章破图。
    """
    if not sid:
        raise HTTPException(401, "需登录")
    rels, seen_rel = [], set()
    for r in (req.rel_paths or []):
        r = (r or "").replace("\\", "/").strip()
        if r and r not in seen_rel:
            seen_rel.add(r)
            rels.append(r)
    if not rels:
        raise HTTPException(400, "rel_paths 不能为空")

    data = _load_collections()
    by_rel = {}
    for c in (data.get(sid, {}) or {}).get("collections", []):
        for it in c.get("items", []):
            rel = (it.get("rel_path") or "").replace("\\", "/")
            if rel:
                by_rel.setdefault(rel, it)

    idx = _load_image_index(sid)
    per_item = []
    tot_added = tot_dedup = tot_restored = 0
    for rel in rels:
        it = by_rel.get(rel)
        row = {"rel_path": rel, "title": (it or {}).get("title", ""),
               "found": 0, "added": 0, "dedup": 0, "restored": 0,
               "already_asset": 0, "skipped": [], "reason": ""}
        if not it:
            row["reason"] = "不属于你或条目不存在"
            per_item.append(row)
            continue
        if not rel.lower().endswith(".html"):
            row["reason"] = "不是图文条目"
            per_item.append(row)
            continue
        ap = os.path.join(DOWNLOADS, rel)
        if not os.path.isfile(ap):
            row["reason"] = "正文文件不存在"
            per_item.append(row)
            continue
        try:
            with open(ap, encoding="utf-8", errors="ignore") as f:
                html_text = f.read()
        except Exception as e:
            row["reason"] = "读取正文失败：%s" % e
            per_item.append(row)
            continue

        # 候选：正文图（按出现顺序去重）+ 封面（置顶，只取一张）
        cands, seen_abs = [], set()
        for ipath in (it.get("images") or []):
            ipath = (ipath or "").replace("\\", "/")
            stem = os.path.splitext(os.path.basename(ipath))[0].lower()
            if stem == "cover":
                p = os.path.join(DOWNLOADS, ipath)
                if os.path.isfile(p):
                    cands.append(p)
                    seen_abs.add(os.path.abspath(p))
                break
        for s in _article_img_srcs(html_text):
            if "/api/image/" in s:
                row["already_asset"] += 1
                continue
            p = _resolve_pool_image(rel, s)
            if not p:
                continue
            k = os.path.abspath(p)
            if k in seen_abs:
                continue
            seen_abs.add(k)
            cands.append(p)
        cands = cands[:ARTICLE_IMG_MAX_PER_ARTICLE]
        row["found"] = len(cands)

        label = re.sub(r"\s+", " ", (row["title"] or "")).strip()[:16].strip(" _-.,，。:：、")
        for p in cands:
            base_name = os.path.basename(p)
            ext = os.path.splitext(base_name)[1].lower()
            if ext not in IMG_EXTS:
                row["skipped"].append(base_name)
                continue
            try:
                if os.path.getsize(p) > ARTICLE_IMG_MAX_BYTES:
                    row["skipped"].append(base_name)
                    continue
                with open(p, "rb") as r:
                    blob = r.read()
            except Exception:
                row["skipped"].append(base_name)
                continue
            iid, dedup, restored = _image_put_bytes(
                sid, idx, blob, ext, (label + "_" + base_name) if label else base_name)
            if dedup:
                row["dedup"] += 1
                tot_dedup += 1
            else:
                row["added"] += 1
                tot_added += 1
            if restored:
                row["restored"] += 1
                tot_restored += 1
        per_item.append(row)

    if tot_added or tot_dedup:
        _save_image_index(sid, idx)
    return {"ok": True, "per_item": per_item,
            "total_added": tot_added, "total_dedup": tot_dedup,
            "total_restored": tot_restored}

@app.get("/api/image/list")
def image_list(sid: str = Depends(current_identity)):
    """列出本人图片，带 used 标记（是否仍被【本人】文章引用）与 trashed 状态。"""
    idx = _load_image_index(sid)
    used = _article_used_image_ids(sid)
    items = []
    for iid, m in idx.items():
        items.append({"id": iid, "url": "/api/image/" + iid,
                      "name": m.get("name", iid), "size": m.get("size", 0),
                      "added_at": m.get("added_at", 0),
                      "ext": m.get("ext", ""),
                      "used": iid in used, "trashed": bool(m.get("trashed"))})
    items.sort(key=lambda x: x.get("added_at", 0), reverse=True)
    return {"ok": True, "items": items, "used_count": sum(1 for i in items if i["used"])}

@app.get("/api/image/{iid}")
def image_get(iid: str, share: str = None, sid: str = Depends(current_identity)):
    """取图：本人隔离；共享视图带 ?share=token 时按令牌 owner 放行。"""
    owner = sid
    if share:
        tok = _resolve_share(share)
        if not tok:
            raise HTTPException(404, "分享链接无效或已失效")
        owner = tok.get("owner") or sid
    idx = _load_image_index(owner)
    m = idx.get(iid)
    if not m:
        raise HTTPException(404, "图片不存在或无权访问")
    ext = m.get("ext", "")
    p = os.path.abspath(os.path.join(_image_root(owner), iid + ext))
    root = os.path.abspath(_image_root(owner))
    if not p.startswith(root + os.sep) or not os.path.isfile(p):
        raise HTTPException(404, "图片文件不存在")
    mime = {".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
            ".webp": "image/webp", ".gif": "image/gif"}.get(ext, "image/png")
    return FileResponse(p, media_type=mime)

class ImageTrashReq(BaseModel):
    ids: list[str] = []

@app.post("/api/image/trash")
def image_trash(req: ImageTrashReq, sid: str = Depends(current_identity)):
    """手动把未使用图片移入回收站（逻辑标记 trashed，不删物理文件）。
    在用图片一律拒绝，避免文章破图。"""
    idx = _load_image_index(sid)
    used = _article_used_image_ids(sid)
    trashed, rejected = [], []
    for iid in req.ids:
        if iid not in idx:
            continue
        if iid in used:
            rejected.append({"id": iid, "name": idx[iid].get("name", iid), "reason": "仍被文章引用"})
            continue
        idx[iid]["trashed"] = True
        idx[iid]["trashed_at"] = int(time.time())
        trashed.append({"id": iid, "name": idx[iid].get("name", iid)})
    _save_image_index(sid, idx)
    return {"ok": True, "trashed": trashed, "rejected": rejected}

@app.post("/api/image/restore")
def image_restore(req: ImageTrashReq, sid: str = Depends(current_identity)):
    idx = _load_image_index(sid)
    restored = []
    for iid in req.ids:
        if iid in idx and idx[iid].get("trashed"):
            idx[iid]["trashed"] = False
            idx[iid].pop("trashed_at", None)
            restored.append(iid)
    _save_image_index(sid, idx)
    return {"ok": True, "restored": restored}

@app.post("/api/image/purge")
def image_purge(req: ImageTrashReq, sid: str = Depends(current_identity)):
    """永久删除：仅删「已进回收站且无引用」的图片；在用图即使标记 trashed 也拒绝。"""
    idx = _load_image_index(sid)
    used = _article_used_image_ids(sid)
    root = os.path.abspath(_image_root(sid))
    purged, skipped = [], []
    for iid in req.ids:
        m = idx.get(iid)
        if not m or not m.get("trashed"):
            skipped.append({"id": iid, "reason": "未在回收站中"})
            continue
        if iid in used:
            skipped.append({"id": iid, "reason": "仍被文章引用"})
            continue
        ext = m.get("ext", "")
        p = os.path.abspath(os.path.join(root, iid + ext))
        if p.startswith(root + os.sep) and os.path.isfile(p):
            os.remove(p)
        idx.pop(iid, None)
        purged.append(iid)
    _save_image_index(sid, idx)
    return {"ok": True, "purged": purged, "skipped": skipped}


# ---------- 富文本文章保存：服务端白名单清洗 + 入池 ----------
# 前端也会清洗一次，但前端可被绕过 → 服务端是安全底线。
_ART_ALLOWED_TAGS = {
    "p", "br", "h1", "h2", "h3", "h4", "h5", "h6", "strong", "b", "em", "i",
    "u", "s", "ul", "ol", "li", "blockquote", "pre", "code", "hr", "section",
    "div", "span", "a", "img", "table", "thead", "tbody", "tr", "td", "th", "figure", "figcaption",
}
_ART_ALLOWED_ATTRS = {
    "a": {"href", "title"},
    "img": {"src", "alt", "width", "height"},
    "td": {"colspan", "rowspan"}, "th": {"colspan", "rowspan"},
}
_ART_CSS_SAFE = (
    "color", "background-color", "font-size", "font-weight", "font-style", "text-align",
    "text-indent", "line-height", "letter-spacing", "margin", "margin-top", "margin-bottom",
    "margin-left", "margin-right", "padding", "padding-top", "padding-bottom", "padding-left",
    "padding-right", "border", "border-top", "border-right", "border-bottom", "border-left",
    "border-color", "border-width", "border-style", "border-radius", "max-width", "width",
)
_ART_CSS_DANGEROUS = ("url(", "expression(", "behavior", "@import", "var(", "!important", "<", ">", "{", "}")

def _clean_art_style(val):
    """CSS 白名单：按属性名字母序确定性输出，危险值整条丢弃。"""
    out = []
    for decl in (val or "").split(";"):
        if ":" not in decl:
            continue
        prop, v = decl.split(":", 1)
        prop, v = prop.strip().lower(), v.strip()
        if prop not in _ART_CSS_SAFE or len(v) > 200:
            continue
        if any(d in v.lower() for d in _ART_CSS_DANGEROUS):
            continue
        if prop == "display" and v == "none":
            continue
        out.append((prop, v))
    return ";".join(p + ":" + v for p, v in sorted(out))

class _ArtSanitizer(HTMLParser):
    """白名单重建：只保留安全标签/属性；script/iframe/style 标签及事件属性一律丢弃。"""
    VOID = {"br", "hr", "img"}
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self._skip_depth = 0
        self._skip_tags = {"script", "style", "iframe", "object", "embed", "svg", "form", "input", "textarea"}
    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if self._skip_depth:
            if tag in self._skip_tags:
                self._skip_depth += 1
            return
        if tag in self._skip_tags:
            self._skip_depth = 1
            return
        if tag not in _ART_ALLOWED_TAGS:
            return
        safe = {}
        for k, v in attrs:
            k = (k or "").lower()
            v = v or ""
            if k.startswith("on") or k == "srcset":     # 事件属性 / srcset 一律丢
                continue
            if k == "style":                             # 所有允许标签都接受清洗后的 style
                pass
            elif tag not in _ART_ALLOWED_ATTRS or k not in _ART_ALLOWED_ATTRS[tag]:
                continue
            if k == "href" and not re.match(r"^(https?://|mailto:|#|/)", v, re.I):
                continue
            if k == "src":
                # 只放行本人图片引用 / data 图 / 相对文件名；禁外链 http（防盗链/追踪）与 javascript
                if not re.match(r"^(/api/image/[A-Za-z0-9_-]+|data:image/|[\w.\-/]+\.(png|jpe?g|gif|webp))$", v, re.I):
                    continue
            if k == "style":
                v = _clean_art_style(v)
                if not v:
                    continue
            safe[k] = v
        attr_s = "".join(f' {k}="{html_escape(v, quote=True)}"' for k, v in safe.items())
        self.parts.append(f"<{tag}{attr_s}>")   # VOID 标签不输出闭合；由 handle_endtag 统一跳过
    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag.lower() not in self.VOID:
            self.handle_endtag(tag)
    def handle_endtag(self, tag):
        tag = tag.lower()
        if self._skip_depth:
            if tag in self._skip_tags:
                self._skip_depth = max(0, self._skip_depth - 1)
            return
        if tag in self.VOID or tag not in _ART_ALLOWED_TAGS:
            return
        self.parts.append(f"</{tag}>")
    def handle_data(self, data):
        if not self._skip_depth:
            self.parts.append(html_escape(data, quote=False))
    def cleaned(self):
        return "".join(self.parts)

def html_escape(s, quote=False):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;" if quote else '"').replace("'", "&#x27;" if quote else "'"))

_ART_DOC_HEAD = ('<!doctype html><html><head><meta charset="utf-8"><title>'
                 + '图文</title><style>')
_ART_DOC_CSS = (
    'body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;font-size:16px;'
    'line-height:1.8;color:#222;max-width:760px;margin:0 auto;padding:24px;word-break:break-word}'
    'h1{font-size:26px}h2{font-size:22px;margin:24px 0 12px}h3{font-size:19px}'
    'blockquote{border-left:4px solid #4a90e2;padding:8px 16px;margin:16px 0;background:#f7f9fc;color:#555}'
    'pre{background:#f6f6f6;padding:14px;border-radius:6px;overflow-x:auto;line-height:1.6}'
    'code{background:#eef1f6;padding:1px 5px;border-radius:4px;font-size:14px}'
    'pre code{background:none;padding:0}'
    'a{color:#576b95;text-decoration:none}'
    'img{max-width:100%;height:auto;display:block;margin:16px auto;border-radius:4px}'
    'table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:8px}'
)
_ART_DOC_TAIL_MID = '</style></head><body>'

def _build_article_html(title, body_html, author="", published_at=""):
    s = _ArtSanitizer()
    s.feed(body_html or "")
    clean = s.cleaned()
    meta = ""
    if author or published_at:
        meta = "<p><small>" + html_escape(" · ".join(x for x in (author, published_at) if x)) + "</small></p>"
    return (_ART_DOC_HEAD + _ART_DOC_CSS + _ART_DOC_TAIL_MID
            + "<h1>" + html_escape(title or "未命名图文") + "</h1>" + meta + clean
            + "</body></html>")

class ArticleSaveReq(BaseModel):
    title: str = ""
    html: str = ""
    published_at: str = ""
    content_type: str = ""
    url: str = ""
    cid: str = "default"
    rid: str = ""          # 编辑已有文章时传原 rid；新建留空由内容派生

@app.post("/api/article/save")
def article_save(req: ArticleSaveReq, sid: str = Depends(current_identity)):
    """保存富文本图文：服务端清洗 → 生成完整 HTML → 复用 _ingest_into_pool 的
    wechat_article 分支入池（与采集图文同构，卡片/阅读器/共享/回收站全继承）。
    rid 传入则复用（编辑场景，旧版本自动进回收站）；否则按内容派生（新建）。"""
    title = (req.title or "").strip() or "未命名图文"
    doc = _build_article_html(title, req.html, published_at=req.published_at)
    raw = doc.encode("utf-8")
    h = hashlib.sha256(raw).hexdigest()
    rid = (req.rid or "").strip() or ("r" + h[:15])
    body_key8 = _body_key8_from_hash(h)
    stage_dir = os.path.join(user_root(sid), "_staging")
    os.makedirs(stage_dir, exist_ok=True)
    staged = _uniq_path(os.path.join(stage_dir, "article_" + h[:10] + ".html"))
    with open(staged, "wb") as w:
        w.write(raw)
    out_rid, dedup, rel, replaced = _ingest_into_pool(
        sid, rid, body_key8, staged, [], title, target_cid=req.cid,
        content_sha256=h, source_type="wechat_article", url=req.url,
        published_at=req.published_at, content_type=req.content_type)
    return {"ok": True, "rid": out_rid, "rel_path": rel, "dedup": dedup,
            "replaced_rel_path": replaced or ""}


@app.post("/api/oo/callback")
async def oo_callback(req: dict, request: Request, sid: str = Depends(current_identity)):
    """ONLYOFFICE 保存回调（默认关闭）。
    仅 status 2/6 落盘；签名 + host 白名单双闸门；按 document.key 幂等；
    回写走 _ingest_into_pool 派生新版本（旧版自动进回收站）。
    ⚠️ 无论成功失败都必须返回 {"error":0}，非 0 编辑器判定保存失败。

    ⚠️ 归属/签名参数在 **query** 上，不在 body 里：文档服务回调是把 callbackUrl
    原样 POST（body 只有 status/url/key 等编辑器字段），所以 email/exp/sig 必须从
    request.query_params 读。曾只读 body 导致 owner 恒空 → 保存永远静默丢弃。
    """
    _oo_guard()
    import urllib.request
    q = request.query_params
    status = req.get("status")
    key = str(req.get("key") or q.get("key") or "")
    if status not in (2, 6) or not req.get("url"):
        return {"error": 0}   # 非保存态（1=编辑中/3=错误）只忽略

    # 身份：文档服务从可信网段带 X-User-Email；未走网关时靠 callbackUrl query 的 email 兜底
    owner = sid or (q.get("email") or "").strip() or str(req.get("email") or "").strip()
    if not owner:
        _oo_warn("callback 无 owner", key)
        return {"error": 0}
    exp = int(req.get("exp") or q.get("exp") or 0)
    sig = str(req.get("sig") or q.get("sig") or "")
    if not _oo_sig_ok(f"cb|{key}|{owner}", exp, sig):
        _oo_warn("callback 验签失败（可能 RM 重启换了签名密钥或已过期）", key)
        return {"error": 0}
    if _oo_key_seen(owner, key):
        return {"error": 0}

    dl_url = str(req.get("url") or "")
    if not _oo_dl_host_allowed(dl_url):
        _oo_warn("callback 下载地址不在可信主机白名单: " + dl_url.split("?")[0], key)
        return {"error": 0}

    # rid 从 key 解析：<rid>_v<version>
    rid = key.rsplit("_v", 1)[0] if "_v" in key else ""
    if not rid:
        _oo_warn("callback key 不含 _v<版本>", key)
        return {"error": 0}
    # 取原资源标题（找不到就退化成 rid 本身）
    title = rid
    for c in _sid_collections(owner):
        for it in c.get("items", []):
            if _rid_of_item(it) == rid:
                title = it.get("title") or rid
                break
        else:
            continue
        break

    try:
        _dl = _rewrite_dl_host(dl_url)
        with urllib.request.urlopen(_dl, timeout=60) as r:
            raw = r.read()
        if len(raw) > 50 * 1024 * 1024:
            _oo_warn("回写文件超过 50MB，已忽略", key)
            return {"error": 0}
        h = hashlib.sha256(raw).hexdigest()
        body_key8 = _body_key8_from_hash(h)
        # 扩展名从原资源 rel_path 推断，保持源格式（不写死 .xlsx）
        ext = ".docx"
        for rel in _resource_paths(owner, rid):
            e = os.path.splitext(rel)[1].lower()
            if e in OFFICE_EXT:
                ext = e
                break
        stage_dir = os.path.join(user_root(owner), "_staging")
        os.makedirs(stage_dir, exist_ok=True)
        # 落盘文件名沿用资源标题：用 oo_<hash> 命名会让池内文件名（进而编辑器标题栏、
        # 下载名）在每次保存后变成一串哈希，用户看不出这是自己那份文档。
        staged = _uniq_path(os.path.join(stage_dir, _safe_upload_name((title or rid) + ext)))
        with open(staged, "wb") as w:
            w.write(raw)
        _ingest_into_pool(owner, rid, body_key8, staged, [], title,
                          target_cid="default", content_sha256=h, source_type="office",
                          keep_versions=True)
        _oo_mark_key(owner, key)
        _oo_version_bump(owner, rid, body_key8=body_key8, size=len(raw), ext=ext, title=title)
        print(f"[oo] 已回写 {len(raw)}B <- {key} (v{_oo_version_get(owner, rid)})", flush=True)
    except Exception as e:
        # 失败也回 0（非 0 编辑器会判定保存失败并反复重试）；但必须留痕，否则"存了没变"查无实据
        _oo_warn(f"回写失败: {type(e).__name__}: {e} | url={_rewrite_dl_host(dl_url)}", key)
    return {"error": 0}


LLM_BASE_URL = str(cfg.get("llm_base_url") or "").rstrip("/")

LLM_API_KEY = str(cfg.get("llm_api_key") or "")

LLM_MODEL = str(cfg.get("llm_model") or "qwen/qwen3.6-35b-a3b")

try:
    LLM_TIMEOUT = int(cfg.get("llm_timeout") or 300)
except (TypeError, ValueError):
    LLM_TIMEOUT = 300

OCR_MODEL = str(cfg.get("ocr_model") or "allenai/olmocr-2-7b")

ARTICLE_MAX_SOURCE_CHARS = 30000

ARTICLES_DIR = os.path.join(DOWNLOADS, "_articles")

os.makedirs(ARTICLES_DIR, exist_ok=True)

_TEMPLATES_FILE = os.path.join(ARTICLES_DIR, "templates.json")

_templates_lock = threading.Lock()

_templates_cache = None

DEFAULT_TEMPLATE_ID = "science-popular"

DEFAULT_TEMPLATE_NAME = "科普/教程文章改写"

DEFAULT_TEMPLATE_CONTENT = """# Role
你是一位拥有10年经验的资深科普文章编辑。擅长将晦涩难懂的学术讲座或口语化的播客内容，改写成逻辑清晰、通俗易懂且引人入胜的科普文章。
# Task
请阅读用户提供的【待处理文本】，将其整理成一篇结构化的文章。
# Constraints & Formatting Rules (至关重要)
1. **原文保留原则**：文章中所有核心观点、金句、数据、案例描述，**必须直接使用原文中的语句**，不得随意paraphrase（意译）或篡改原意。
2. **强制加粗**：所有直接引用自原文的句子或短语，必须使用 Markdown 格式标记为粗体（例如：**这是原文内容**）。
3. **通俗化润色**：在保留原文粗体句的基础上，你可以添加连接词、过渡句、小标题和总结性语言，使文章读起来像一篇成熟的公众号推文，而不是生硬的转录稿。
4. **结构要求**：
- 请为文章起一个吸引人的标题。
- 使用清晰的小标题划分段落。
- 遇到复杂的科学原理，请用生活中的类比进行解释（但在解释后，仍需附上原文的粗体表述）。
# Workflow
1. 分析【待处理文本】的逻辑脉络。
2. 提取关键信息点。
3. 按照“通俗易懂的引导语 + **原文核心句（加粗）**”的模式重组内容。
4. 输出最终的 Markdown 格式文章。"""

_ARTICLE_TASKS = {}

_ARTICLE_TASKS_LOCK = threading.Lock()

_ARTICLE_BATCHES = {}

_ARTICLE_BATCH_LOCK = threading.Lock()

def _builtin_templates():
    """代码内置的只读模板：每个身份都可见、不可删；保存内置即「另存为用户副本」。"""
    return [{
        "id": DEFAULT_TEMPLATE_ID,
        "name": DEFAULT_TEMPLATE_NAME,
        "content": DEFAULT_TEMPLATE_CONTENT,
        "builtin": True,
        "updated_at": 0,
    }]

def _read_or_init_templates():
    """读取 templates.json；自动从 v1（{"templates":[...]}）迁移到 v2（按身份分桶）。幂等。"""
    data = None
    if os.path.isfile(_TEMPLATES_FILE):
        try:
            with open(_TEMPLATES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = None
    # 已是 v2 结构
    if isinstance(data, dict) and data.get("version") == 2 and isinstance(data.get("users"), dict):
        return data
    # 需要从 v1 迁移，或文件缺失/损坏 → 重新初始化
    new = {"version": 2, "users": {}}
    legacy = []
    if isinstance(data, dict) and isinstance(data.get("templates"), list):
        legacy = [t for t in data["templates"] if not t.get("builtin")]
    if legacy:
        # 旧的非内置模板无归属信息：写入「已有文章的各用户桶 + 匿名桶」，尽量保留可见性
        hashes = set()
        adir = os.path.join(ARTICLES_DIR, "users")
        if os.path.isdir(adir):
            for h in os.listdir(adir):
                if os.path.isdir(os.path.join(adir, h)):
                    hashes.add(h)
        hashes.add(user_hash(None))
        for h in hashes:
            new["users"][h] = {"templates": [dict(t) for t in legacy]}
    new["users"].setdefault(user_hash(None), {"templates": []})
    try:
        with open(_TEMPLATES_FILE, "w", encoding="utf-8") as f:
            json.dump(new, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[article] 模板初始化落盘失败: {e}", flush=True)
    return new

def _load_article_templates(sid):
    """按身份返回模板：内置（只读）+ 该用户自定义模板，二者分桶隔离。"""
    global _templates_cache
    if _templates_cache is None:
        with _templates_lock:
            if _templates_cache is None:
                _templates_cache = _read_or_init_templates()
    data = _templates_cache
    bucket = (data.get("users") or {}).get(user_hash(sid)) or {}
    user_tpls = bucket.get("templates", [])
    return {"builtin": _builtin_templates(), "templates": user_tpls}

def _save_article_templates():
    """仅落盘，不加锁、不调用 _load_article_templates（避免与不可重入锁构成死锁）。"""
    global _templates_cache
    with _templates_lock:
        try:
            with open(_TEMPLATES_FILE, "w", encoding="utf-8") as f:
                json.dump(_templates_cache or {"version": 2, "users": {}}, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[article] 模板保存失败: {e}", flush=True)

def _article_art_dir(sid):
    d = os.path.join(ARTICLES_DIR, "users", user_hash(sid))
    os.makedirs(d, exist_ok=True)
    return d


def _rid_body_from_rel(rel):
    """从字幕/资源 rel_path 解析 (rid, body_key8)。rel 形如 resources/<rid>/<body>/<stem>.txt。
    C 方案文章实体按此定位到资源 body 目录下的用户子桶。无法解析时返回 (None, None)。"""
    parts = (rel or "").replace("\\", "/").split("/")
    if len(parts) >= 3 and parts[0] == "resources":
        return parts[1], parts[2]
    return None, None


def _article_resource_md_dir(rid, body_key8, sid):
    """C 方案：文章 .md 实体物理共置于资源 body 目录下的「用户子桶」，随资源删除级联回收。
    路径：RESOURCES_DIR/<rid>/<body_key8>/users/<user_hash(sid)>/"""
    d = os.path.join(RESOURCES_DIR, rid, body_key8, "users", user_hash(sid))
    os.makedirs(d, exist_ok=True)
    return d


def _article_rels_for_resource(rid, body_key8=None, sid=None):
    """C 方案：返回某资源下 AI 文章 .md 的 DOWNLOADS 相对路径列表。
    文章索引集中存于用户级 _articles/users/<hash>/index.json（便于列举），文章实体 .md 则物理共置于
    resources/<rid>/<body>/users/<hash>/（随资源删除级联回收）。本函数按 resource_id（及可选 body_key8）
    从用户级索引筛出该资源的文章条目，再用 resources 目录拼出 .md 相对路径。
    - sid 给定：只返回该用户桶内的文章（多用户各自生成、互不串）。
    - sid 为 None：返回该资源下所有用户桶的文章（用于共享资源聚合）。"""
    if not rid:
        return []
    if sid is not None:
        hashes = [user_hash(sid)]
    else:
        users_base = os.path.join(ARTICLES_DIR, "users")
        hashes = os.listdir(users_base) if os.path.isdir(users_base) else []
    out = []
    for h in hashes:
        idx_p = os.path.join(ARTICLES_DIR, "users", h, "index.json")
        try:
            idx = json.load(open(idx_p, encoding="utf-8"))
        except Exception:
            idx = {}
        for stem, meta in idx.items():
            if meta.get("resource_id") != rid:
                continue
            if body_key8 and meta.get("body_key8") != body_key8:
                continue
            _r, _b = meta.get("resource_id"), meta.get("body_key8")
            if not (_r and _b):
                continue
            md = os.path.join(RESOURCES_DIR, _r, _b, "users", h, stem + ".md")
            if os.path.isfile(md):
                out.append(os.path.relpath(md, DOWNLOADS).replace("\\", "/"))
    return out


def _article_stem(task_id):
    """校验并归一化文章文件名 stem：禁止路径穿越，允许中文等任意非危险字符。"""
    s = (task_id or "").strip()
    if not s or "/" in s or "\\" in s or s in (".", ".."):
        return None
    return s

def _article_index_path(sid):
    return os.path.join(_article_art_dir(sid), "index.json")

def _load_article_index(sid):
    """文章持久化索引（含来源字幕 rel_path 等）。重启后卡片关联/粗体命中不丢。"""
    p = _article_index_path(sid)
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (FileNotFoundError, ValueError):
        pass
    return {}

def _save_article_index(sid, data):
    p = _article_index_path(sid)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, p)

def _article_bold_for(owner, stem, sub_rel=None):
    """文章「粗体保真」元数据（命中率 + 未命中片段）。

    优先读持久化索引；若存量文章索引未记录 bold_bad（旧版生成），
    则在源字幕仍存在时现场重算兜底（对人工编辑过的文章同样适用）。
    返回 {bold_rate, bold_hit, bold_total, bold_bad}；无数据时 bold_bad 为空列表。
    """
    if not owner or not stem:
        return {"bold_rate": None, "bold_hit": None, "bold_total": None, "bold_bad": []}
    meta = dict(_load_article_index(owner).get(stem) or {})
    rate, hit, total = meta.get("bold_rate"), meta.get("bold_hit"), meta.get("bold_total")
    bad = meta.get("bold_bad")
    rel = (sub_rel or meta.get("rel_path") or "").replace("\\", "/")
    if bad is None and rel:
        art_p = os.path.join(_article_art_dir(owner), stem + ".md")
        sub_p = os.path.join(DOWNLOADS, rel)
        if os.path.isfile(art_p) and os.path.isfile(sub_p):
            try:
                with open(art_p, "r", encoding="utf-8") as f:
                    art = f.read()
                src = _read_subtitle_text(sub_p)
                hit, total, bad = _bold_fidelity(art, src)
                rate = (round(hit * 100 / total) if total else None)
            except Exception:
                bad = []
    return {"bold_rate": rate, "bold_hit": hit, "bold_total": total, "bold_bad": bad or []}

def _llm_models():
    """透传 LM Studio /v1/models，供前端下拉选择。"""
    import urllib.request
    if not LLM_BASE_URL:
        return []
    req = urllib.request.Request(LLM_BASE_URL + "/models")
    if LLM_API_KEY:
        req.add_header("Authorization", "Bearer " + LLM_API_KEY)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        return [m.get("id") for m in (data.get("data") or []) if m.get("id")]
    except Exception:
        return []

def _llm_chat(messages, model=None, temperature=0.6, timeout=None):
    """调用 OpenAI 兼容 /chat/completions。成功返回 (True, 正文)，失败返回 (False, 错误说明)。"""
    import urllib.request
    import urllib.error
    if not LLM_BASE_URL:
        return False, "未配置模型服务地址（llm_base_url）"
    payload = {
        "model": model or LLM_MODEL,
        "messages": messages,
        "temperature": temperature,
        "stream": False,
        # Qwen3 系列默认开启 thinking，会向正文注入 <think>…</think> 块污染文章；
        # 关闭它（对非 thinking 模型无副作用）。与本地 LangGraph 后端保持一致。
        "chat_template_kwargs": {"enable_thinking": False},
    }
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(LLM_BASE_URL + "/chat/completions", data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if LLM_API_KEY:
        req.add_header("Authorization", "Bearer " + LLM_API_KEY)
    try:
        with urllib.request.urlopen(req, timeout=timeout or LLM_TIMEOUT) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")[:400]
        except Exception:
            pass
        return False, f"模型服务返回 HTTP {e.code}：{detail}"
    except Exception as e:
        return False, f"调用模型失败（{type(e).__name__}）：{e}"
    try:
        content = ((data.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
    except Exception:
        content = ""
    if not content.strip():
        return False, "模型返回内容为空：" + json.dumps(data, ensure_ascii=False)[:300]
    return True, content

def _llm_chat_vision(messages, model=None, temperature=0.0, timeout=None, max_tokens=512):
    """多模态（图文）调用 OpenAI 兼容 /chat/completions。
    messages 元素形如 {"role","content"}，content 可为 str，或
    [{"type":"text","text":...}, {"type":"image_url","image_url":{"url":"data:image/jpeg;base64,..."}}]。
    成功返回 (True, 正文)，失败返回 (False, 错误说明)。"""
    import urllib.request
    import urllib.error
    if not LLM_BASE_URL:
        return False, "未配置模型服务地址（llm_base_url）"
    payload = {
        "model": model or OCR_MODEL,
        "messages": messages,
        "temperature": temperature,
        "stream": False,
        # ⚠ 必须显式给 max_tokens：不传时依赖服务端默认值（偏小），
        #   拼图要输出 6 行、正文较长时会被截断 → 表现为「偶发漏格」，需靠补齐兜底。
        "max_tokens": max_tokens,
        # 关闭 thinking（对非 thinking 模型无副作用），与 _llm_chat 保持一致
        "chat_template_kwargs": {"enable_thinking": False},
    }
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(LLM_BASE_URL + "/chat/completions", data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if LLM_API_KEY:
        req.add_header("Authorization", "Bearer " + LLM_API_KEY)
    try:
        with urllib.request.urlopen(req, timeout=timeout or LLM_TIMEOUT) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")[:400]
        except Exception:
            pass
        return False, f"模型服务返回 HTTP {e.code}：{detail}"
    except Exception as e:
        return False, f"调用模型失败（{type(e).__name__}）：{e}"
    try:
        content = ((data.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
    except Exception:
        content = ""
    if not content.strip():
        return False, "模型返回内容为空"
    return True, content

def _olmocr_system_prompt():
    """olmOCR 风格的 OCR 指令：只输出画面中可见字幕文本，避免把背景/论文/书脊等杂文字混读进来。"""
    return (
        "You are an advanced OCR model trained on the olmOCR dataset. "
        "The image shows the bottom subtitle band cropped from a video frame. "
        "Extract ONLY the subtitle text visible in the image, keeping its original language and natural reading order. "
        "Output plain text without any markdown, headings, or commentary. "
        "If there is no readable subtitle in the image, output exactly: 无字幕"
    )

def _clean_ocr_text(txt: str) -> str:
    """清理 olmOCR 可能夹带的反引号围栏 / 首尾空白，保留内部换行。"""
    t = (txt or "").strip()
    # 去掉 ```...``` 代码围栏
    if t.startswith("```"):
        t = t.strip("`")
        # 去掉首行可能的语言标记
        t = re.sub(r"^\s*\w+\s*\n", "", t, count=1)
    return t.strip()

def _detect_embedded_subtitle(video_path: str, log_cb, model: str = None, sample_n: int = 24,
                              progress_cb=None):
    """前置检验：均匀抽 sample_n 帧，裁底部字幕带，问模型『该区域是否有字幕文字』。
    返回 (detected, total, status)。detected>=1 即视为存在内嵌字幕。
    一次 ffmpeg 抽完所有样帧（不再逐帧 -ss），顺序（workers=1）识别，
    避免 LM Studio 并发劣化；采样数由 12 提到 24，检验更可靠。"""
    import subprocess
    import base64
    import shutil
    import tempfile
    ffmpeg = resolve_ffmpeg()
    if not ffmpeg or not os.path.isfile(ffmpeg):
        log_cb("[OCR预检] ⚠ 未找到 ffmpeg，无法抽帧")
        return 0, 0, "no_ffmpeg"
    ffprobe = os.path.join(os.path.dirname(ffmpeg), "ffprobe")
    if not os.path.isfile(ffprobe):
        log_cb("[OCR预检] ⚠ 未找到 ffprobe，无法获取时长")
        return 0, 0, "no_ffprobe"
    try:
        dur_s = float(subprocess.check_output(
            [ffprobe, "-v", "error", "-show_entries", "format=duration",
             "-of", "default=noprint_wrappers=1:nokey=1", video_path],
            text=True, stderr=subprocess.DEVNULL).strip())
    except Exception as e:
        log_cb(f"[OCR预检] ⚠ 获取时长失败：{e}")
        return 0, 0, "no_duration"
    if dur_s <= 0:
        return 0, 0, "zero_duration"
    n = max(1, min(sample_n, int(dur_s) or 1))
    vf = "fps=%s,crop=iw:ih*0.28:0:ih*0.72,scale=800:-1" % (n / dur_s)
    tmp = tempfile.mkdtemp(prefix="ocr_pre_")
    cmd = [ffmpeg, "-v", "error", "-i", video_path, "-vf", vf,
           "-frames:v", str(n), "-start_number", "0",
           os.path.join(tmp, "p%04d.jpg"), "-y"]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120, check=False)
    except Exception as e:
        log_cb(f"[OCR预检] ⚠ 抽帧异常：{e}")
    frames = []
    for i in range(n):
        fp = os.path.join(tmp, f"p{i:04d}.jpg")
        if os.path.isfile(fp) and os.path.getsize(fp) > 1000:
            frames.append((i, fp))
    if not frames:
        shutil.rmtree(tmp, ignore_errors=True)
        log_cb("[OCR预检] ⚠ 抽帧失败（ffmpeg 无输出）")
        return 0, 0, "no_frames"
    log_cb(f"[OCR预检] 均匀抽 {len(frames)} 帧检测内嵌字幕（顺序识别）...")

    sys_p = ("你是一个字幕检测助手。下方图像是视频某一帧的底部区域。"
             "如果该区域存在『字幕/对白字幕条』（通常是底部居中的白色或浅色文字、常带半透明黑底），"
             "请只回答 YES；如果是画面正文、海报、PPT、文档、水印、UI 等非字幕文字，或该区域没有任何文字，"
             "请只回答 NO。不要输出任何其他内容。")
    user_text = "该图像底部是否有『字幕条』文字？仅回答 YES 或 NO。"

    detected = 0
    for idx, (i, fp) in enumerate(frames, 1):
        try:
            with open(fp, "rb") as f:
                b64 = base64.b64encode(f.read()).decode("ascii")
            msg = [
                {"role": "system", "content": sys_p},
                {"role": "user", "content": [
                    {"type": "text", "text": user_text},
                    {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{b64}"}},
                ]},
            ]
            ok, txt = _llm_chat_vision(msg, model=model, timeout=60)
            if ok and re.search(r"\bYES\b", (txt or "").upper()):
                detected += 1
        except Exception:
            pass
        # 预检占 0-10%，每张回写进度
        if progress_cb:
            progress_cb(max(1, int(10 * idx / max(len(frames), 1))),
                        f"前置检验 {idx}/{len(frames)} 帧")
        if idx % 8 == 0 or idx == len(frames):
            log_cb(f"[OCR预检] 检测进度 {idx}/{len(frames)}")
    shutil.rmtree(tmp, ignore_errors=True)
    return detected, len(frames), "ok"

def _generate_ocr_subtitle(video_path: str, out_dir: str, log_cb, title_hint: str = "",
                           model: str = None, fps: float = 1.0, progress_cb=None):
    """硬字幕 OCR（治本版）：

    1) 一次 ffmpeg 抽帧：fps 可调（0.5/1/2 档位），裁底部 28% 字幕带并缩放，
       用 drawtext 给每帧烧上全局帧号，再用 tile=1x6 竖排拼成 6 帧一张的拼图；
    2) 顺序（workers=1，LM Studio 不适合并发）逐张拼图送 olmOCR，
       按帧号解析出每格字幕；
    3) 以真实帧号换算时间戳（time = 帧号 / fps），相邻相同文本聚类成 SRT/TXT。

    相比旧版的三处根治：
    - 采样密度：旧版被 max_frames=120 上限压成 8.66s/帧（漏 75~80%）；
      本版 0.5~2s/帧，超长视频自动降 fps 到 ≤ MAX_FRAMES 帧。
    - 并发负优化取消：旧版 workers=3 反而 14~16s/帧，本版顺序 0.6~0.9s/帧。
    - 时间戳：旧版用均匀格点；本版用真实帧号，对齐更准。

    返回 (srt_rel, txt_rel, status)；失败时 srt_rel/txt_rel 为 None。"""
    import subprocess
    import base64
    import shutil
    import tempfile
    PER_SHEET = 6          # 每张拼图 1 列 × 6 行（竖排）
    MAX_FRAMES = 1800      # 超长视频自动降 fps 的上限
    # 字幕帧号字体：容器无 fontconfig（fc-list=0），drawtext 必须显式指定 fontfile。
    # 优先用容器基础镜像自带的 DejaVu（保证存在），其次回退到仓库随附字体。
    _here = os.path.dirname(os.path.abspath(__file__))
    _bundled = os.path.join(_here, "assets", "fonts", "DejaVuSans.ttf")
    OCR_FONT = _bundled if os.path.isfile(_bundled) else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    _font_opt = f"fontfile='{OCR_FONT}':" if os.path.isfile(OCR_FONT) else ""
    ffmpeg = resolve_ffmpeg()
    if not ffmpeg or not os.path.isfile(ffmpeg):
        log_cb("[OCR] ⚠ 未找到 ffmpeg，无法抽帧")
        return None, None, "no_ffmpeg"
    ffprobe = os.path.join(os.path.dirname(ffmpeg), "ffprobe")
    if not os.path.isfile(ffprobe):
        log_cb("[OCR] ⚠ 未找到 ffprobe，无法获取时长")
        return None, None, "no_ffprobe"
    # 1) 时长
    try:
        dur_s = float(subprocess.check_output(
            [ffprobe, "-v", "error", "-show_entries", "format=duration",
             "-of", "default=noprint_wrappers=1:nokey=1", video_path],
            text=True, stderr=subprocess.DEVNULL).strip())
    except Exception as e:
        log_cb(f"[OCR] ⚠ 获取时长失败：{e}")
        return None, None, "no_duration"
    if dur_s <= 0:
        return None, None, "zero_duration"
    # 采样密度：档位 fps，超长视频自动降到 ≤ MAX_FRAMES 帧
    eff_fps = float(fps)
    if dur_s * eff_fps > MAX_FRAMES:
        eff_fps = MAX_FRAMES / dur_s
    total = int(dur_s * eff_fps) + 1
    n_sheets = (total + PER_SHEET - 1) // PER_SHEET
    log_cb(f"[OCR] 视频时长 {dur_s:.1f}s，档位 {fps}fps（实际 {eff_fps:.2f}fps），"
           f"约 {total} 帧 → {n_sheets} 张拼图（模型 {model or OCR_MODEL}）")

    # 2) 一次抽帧 + 烧帧号 + 拼图（1×6 竖排）
    tmp_frames = tempfile.mkdtemp(prefix="ocr_f_")
    draw = ("drawtext=" + _font_opt +
            "text='%{n}':fontcolor=red:fontsize=22:"
            "box=1:boxcolor=black@0.6:boxborderw=4:"
            "x=w-tw-10:y=h-th-10")
    vf = (f"fps={eff_fps:.6f},"
          "crop=iw:ih*0.28:0:ih*0.72,"
          "scale=800:-1,"
          f"{draw}")
    fr_cmd = [ffmpeg, "-v", "error", "-i", video_path, "-vf", vf,
              "-frames:v", str(total), "-start_number", "0",
              os.path.join(tmp_frames, "f%05d.jpg"), "-y"]
    try:
        subprocess.run(fr_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=300, check=False)
    except Exception as e:
        log_cb(f"[OCR] ⚠ 抽帧异常：{e}")
    got = sorted([f for f in os.listdir(tmp_frames) if f.endswith(".jpg")])
    if not got:
        shutil.rmtree(tmp_frames, ignore_errors=True)
        log_cb("[OCR] ⚠ 抽帧失败（ffmpeg 无输出）")
        return None, None, "no_frames"
    total = len(got)                              # 以实际抽到为准（视频末尾可能不足）
    n_sheets = (total + PER_SHEET - 1) // PER_SHEET
    if progress_cb: progress_cb(10, f"抽帧完成 {total} 帧，正在拼图…")

    sheet_dir = tempfile.mkdtemp(prefix="ocr_sheet_")
    # ⚠ 用「1 列 × 6 行」竖排而非横排 2×3：
    #   实测连续帧字幕相同时，横排布局会偶发被模型把重复格合并（t=900s 处 6 格只回 3 行），
    #   竖排更像一页文档、阅读顺序天然自上而下，实测 3/3 稳定；再配合下面的「缺格补齐」兜底。
    tile_vf = f"tile=1x{PER_SHEET}"
    sh_cmd = [ffmpeg, "-v", "error", "-start_number", "0",
              "-i", os.path.join(tmp_frames, "f%05d.jpg"),
              "-frames:v", str(n_sheets),
              "-vf", tile_vf,
              os.path.join(sheet_dir, "s%04d.jpg"), "-y"]
    try:
        subprocess.run(sh_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=300, check=False)
    except Exception as e:
        log_cb(f"[OCR] ⚠ 拼图异常：{e}")
    sheets = sorted([f for f in os.listdir(sheet_dir) if f.endswith(".jpg")])
    if not sheets:
        shutil.rmtree(tmp_frames, ignore_errors=True)
        shutil.rmtree(sheet_dir, ignore_errors=True)
        log_cb("[OCR] ⚠ 拼图失败（ffmpeg 无输出）")
        return None, None, "no_frames"
    log_cb(f"[OCR] 已生成 {len(sheets)} 张拼图，开始顺序识别...")
    if progress_cb: progress_cb(20, f"已生成 {len(sheets)} 张拼图，开始识别…")

    sys_p = (
        "你是一个专业的硬字幕 OCR 引擎。下方图像是由 6 张连续视频帧拼成的拼图"
        "（1 列 × 6 行，自上而下竖排），每格右下角有红色帧号（如 0、1、2…），那是『帧编号标记』，不是字幕内容。\n"
        "请逐格提取『字幕条』文本（通常是底部居中的对白字幕，忽略画面正文/海报/水印/UI）。\n"
        "输出严格遵循每行一格的格式：  帧号 字幕文本\n"
        "例如：\n"
        "0 今天天气真好\n"
        "1 我们去散步吧\n"
        "2 无字幕\n"
        "若该格没有任何字幕文字，输出：  帧号 无字幕\n"
        "⚠ 即使相邻几格的字幕文字完全相同，也必须各自单独输出一行，绝对不能合并成一行；\n"
        "⚠ 必须输出全部 6 行（帧号 0 到 5），一行都不能少，也不要输出任何额外说明。"
    )
    user_text = "按上面格式逐格输出 6 行字幕（帧号 文本 / 帧号 无字幕）。"

    # 单帧兜底识别（拼图缺格时按帧补跑）：复用 olmOCR 单图提示词
    sys_single = _olmocr_system_prompt()

    def _ocr_single_frame(idx):
        fp = os.path.join(tmp_frames, f"f{idx:05d}.jpg")
        if not os.path.isfile(fp):
            return ""
        try:
            with open(fp, "rb") as f:
                b64 = base64.b64encode(f.read()).decode("ascii")
            msg = [
                {"role": "system", "content": sys_single},
                {"role": "user", "content": [
                    {"type": "text", "text": "提取图像中的字幕文本。"},
                    {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{b64}"}},
                ]},
            ]
            ok, txt = _llm_chat_vision(msg, model=model, timeout=90)
            return _clean_ocr_text(txt) if ok else ""
        except Exception:
            return ""

    # 解析：从模型输出提取「帧号 文本」，仅采信本拼图应有的 6 个帧号，避免其它数字串污染
    line_re = re.compile(r"^\s*(\d+)\s*[:.、)\]］]?\s*(.*)$")

    def _parse_sheet(text, base, count):
        """解析一张拼图 → {全局帧号: 文本}，并返回所用的映射方式。

        ⚠ 不能只信模型读出来的帧号：实测模型会把本该是全局号（如 30~35）的标记
        读成局部号（0~5），一旦按帧号过滤就整张被判「全缺」。
        因此映射优先级：① 期望帧号齐全 → 用帧号；② 行数够 → 按**行序**映射
        （第 i 行 = base+i）；③ 都不满足 → 用已识别的帧号，其余交给缺格补齐。
        """
        rows, numbered = [], {}
        for ln in (text or "").splitlines():
            m = line_re.match(ln)
            if not m:
                continue
            txt = _clean_ocr_text(m.group(2))
            rows.append(txt)
            g = int(m.group(1))
            if base <= g < base + count:
                numbered[g] = txt
        want = set(range(base, base + count))
        if want.issubset(set(numbered.keys())):
            return numbered, "num"
        if len(rows) >= count:
            return {base + i: rows[i] for i in range(count)}, "order"
        return numbered, "partial"

    # 3) 顺序识别（workers=1：LM Studio 并发会劣化到 14~16s/帧）
    #    每张拼图都做「数量校验」：缺格先重问一次，仍缺则退回单帧 OCR 补齐。
    #    （拼图 OCR 偶发把重复格合并，单帧是确定性兜底，保证不漏句。）
    frame_text = {}
    repaired = 0
    by_order = 0
    for si, sf in enumerate(sheets):
        sfp = os.path.join(sheet_dir, sf)
        base = si * PER_SHEET
        cnt = len(range(base, min(base + PER_SHEET, total)))
        expect = set(range(base, base + cnt))
        got = {}
        for attempt in (0, 1):
            try:
                with open(sfp, "rb") as f:
                    b64 = base64.b64encode(f.read()).decode("ascii")
                p = sys_p if attempt == 0 else (
                    sys_p + "\n\n注意：上一次输出遗漏了部分格子，请务必逐格输出全部 6 行，一行都不能少。")
                msg = [
                    {"role": "system", "content": p},
                    {"role": "user", "content": [
                        {"type": "text", "text": user_text},
                        {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{b64}"}},
                    ]},
                ]
                ok, txt = _llm_chat_vision(msg, model=model, timeout=120)
                if ok:
                    parsed, mode = _parse_sheet(txt, base, cnt)
                    got.update(parsed)
                    if mode == "order":
                        by_order += 1
            except Exception:
                pass
            if expect.issubset(set(got.keys())):
                break
        missing = sorted(expect - set(got.keys()))
        if missing:
            for g in missing:
                t1 = _ocr_single_frame(g)
                if (t1 or "").strip():
                    got[g] = t1
            repaired += len(missing)
        frame_text.update(got)
        done = si + 1
        # 每张都回写进度（20% 起，占 75%），前端进度条持续可见；log 仍每 10 张打一次避免刷屏
        if progress_cb:
            _pct = 20 + int(75 * done / max(len(sheets), 1))
            progress_cb(_pct, f"识别 {done}/{len(sheets)} 拼图（{min(done*PER_SHEET, total)}/{total} 帧）")
        if done % 10 == 0 or done == len(sheets):
            log_cb(f"[OCR] 识别进度 {done}/{len(sheets)} 拼图（{min(done*PER_SHEET, total)}/{total} 帧）"
                   + (f"；行序映射 {by_order} 张" if by_order else "")
                   + (f"；缺格补齐累计 {repaired} 帧" if repaired else ""))

    # 4) 聚类：按全局帧号连续、文本相同或高度相似合并；空/无字幕为间隙
    #    治本（2026-11-19）：olmOCR 对同一句字幕会在标点、空格、轻微措辞上抖动
    #    （如「，」/「。」、「要求10%」/「要求 10% 」），旧逻辑只去空白后精确相等，
    #    导致同一句被拆成多段、字幕面板出现重复行。这里改为去标点归一化 + 相似度判定。
    NO_SUB = "无字幕"
    _PUNCT_RE = re.compile(r"[\s，。、；：！？“”‘’（）《》〈〉·—…,.;:!?\"'()\[\]{}<>/\-]")
    def _norm_sub(s):
        """字幕比较归一化：取第一行（硬字幕通常单行；拼图 OCR 偶发把滚动中的
        下一句串到第二行属噪声），去标点/空白后比较。"""
        lines = (s or "").splitlines()
        first = lines[0] if lines else ""
        return _PUNCT_RE.sub("", first)
    def _same_sub(a, b):
        na, nb = _norm_sub(a), _norm_sub(b)
        if not na or not nb:
            return False
        if na == nb:
            return True
        # 长度差过大不判同句，避免把一个短句吞进长句
        if abs(len(na) - len(nb)) > max(len(na), len(nb)) * 0.15:
            return False
        return difflib.SequenceMatcher(None, na, nb).ratio() >= 0.90
    segs = []
    cur_text = None
    cur_start = None
    for g in range(total):
        txt = frame_text.get(g, "")
        if _norm_sub(txt) == _norm_sub(NO_SUB) or not _norm_sub(txt):
            if cur_text is not None:
                segs.append((cur_start, g / eff_fps, cur_text))
                cur_text = None
            continue
        t0 = g / eff_fps
        if cur_text is None:
            cur_start = t0
            cur_text = txt
        elif _same_sub(cur_text, txt):
            pass  # 同一句的标点/空格/轻微措辞差异 → 延续当前段
        else:
            segs.append((cur_start, t0, cur_text))
            cur_start = t0
            cur_text = txt
    if cur_text is not None:
        segs.append((cur_start, min(dur_s, total / eff_fps), cur_text))
    if not segs:
        log_cb("[OCR] ⚠ 未识别到任何硬字幕（可能该视频确实无内嵌字幕）")
        shutil.rmtree(tmp_frames, ignore_errors=True)
        shutil.rmtree(sheet_dir, ignore_errors=True)
        return None, None, "empty"
    # 5) 写 SRT + TXT
    # 用「视频主干 + _字幕」的规范命名，使媒体库/字幕转文章/下载列表等既有链路
    # 能直接识别这份 OCR 字幕（与官方字幕落盘时的命名一致）。
    base = _safe_fname_title(title_hint or os.path.basename(out_dir))
    srt_path = os.path.join(out_dir, f"{base}_字幕.srt")
    txt_path = os.path.join(out_dir, f"{base}_字幕.txt")

    def _srt_time(sec):
        h = int(sec // 3600)
        m = int((sec % 3600) // 60)
        s = int(sec % 60)
        ms = int(round((sec - int(sec)) * 1000))
        if ms == 1000:
            ms = 999
        return f"{h:02d}:{m:02d}:{s:02d},{ms:03d}"

    # ⚠ 覆盖前先备份：官方字幕与 OCR 字幕共用「{标题}_字幕.txt」命名，
    #   直接覆盖会让原字幕不可逆丢失（尤其首次把官方字幕换成内嵌 OCR 的场景）。
    for _p in (srt_path, txt_path):
        if os.path.isfile(_p):
            try:
                shutil.move(_p, f"{_p}.{int(time.time())}.bak")
            except Exception:
                pass
    with open(srt_path, "w", encoding="utf-8") as f:
        for k, (st, en, tx) in enumerate(segs, 1):
            f.write(f"{k}\n{_srt_time(st)} --> {_srt_time(en)}\n{tx}\n\n")
    with open(txt_path, "w", encoding="utf-8") as f:
        for _, _, tx in segs:
            f.write(tx + "\n")
    shutil.rmtree(tmp_frames, ignore_errors=True)
    shutil.rmtree(sheet_dir, ignore_errors=True)
    log_cb(f"[OCR] ✅ 硬字幕识别完成：{len(segs)} 段 → {os.path.basename(srt_path)}")
    return (os.path.relpath(srt_path, DOWNLOADS), os.path.relpath(txt_path, DOWNLOADS), "ok")

class OcrSubtitleReq(BaseModel):
    resource_id: str = ""
    force: bool = False            # 预检 0 命中时仍强制跑全量 OCR
    fps: float = 1.0               # 识别密度档位：0.5 快速 / 1 标准 / 2 精细

@app.post("/api/ocr-subtitle")
def ocr_subtitle(req: OcrSubtitleReq, sid: str = Depends(current_identity)):
    """对媒体库里「已有视频」手动触发硬字幕 OCR（内嵌字幕识别）。

    与下载解耦：下载流程不再自动跑 OCR；此处由用户在媒体库卡片上主动触发，
    并带前置检验（检测视频是否真有内嵌字幕）。返回 task_id，前端轮询 /api/task/{id}。"""
    rid = (req.resource_id or "").strip()
    if not rid:
        raise HTTPException(400, "缺少 resource_id")
    item, _ = _find_resource(sid, rid)
    if not item:
        raise HTTPException(404, "资源不存在或不属于当前用户")
    rel = item.get("rel_path", "")
    if not rel or not os.path.isfile(os.path.join(DOWNLOADS, rel)):
        raise HTTPException(400, "视频文件不存在或已失效（请先重新下载）")
    # 护栏：已有官方字幕的视频不允许用 OCR 覆盖（OCR 质量≤官方字幕，且会改动 .bak 备份指向）
    if item.get("subtitle_source") == "official":
        raise HTTPException(409, "该视频已有官方字幕，不支持用 OCR 覆盖（如需替换为 OCR 字幕，请先删除原字幕再重试）")
    if not LLM_BASE_URL:
        raise HTTPException(500, "服务端未配置模型地址（llm_base_url）")
    now = time.time()
    with tasks_lock:
        # 防重复（单用户全局）：同一 owner 只要有**任一** running 的 OCR 任务，
        # 就不能再发起任何视频的识别（本地模型单并发，多任务只会互相抢算力且进度难追踪）。
        # 命中时复用其 task_id（幂等），并回带该任务占用的 rid，供前端提示用户在识别哪个视频。
        # 僵尸兜底：超过 2 小时仍 running 的视为失效，允许新提交。
        for _tid, _t in tasks.items():
            if (_t.get("type") == "ocr" and _t.get("owner") == sid
                    and _t.get("status") == "running"):
                if now - _t.get("created_at", 0) < 7200:
                    return {"task_id": _tid, "reused": True,
                            "busy_rid": _t.get("resource_id")}
        task_id = uuid.uuid4().hex[:16]
        tasks[task_id] = {
            "id": task_id, "status": "running", "progress": 0.0, "log": [],
            "file": None, "filename": None, "extras": [], "size": 0, "cmd": "",
            "type": "ocr", "owner": sid, "resource_id": rid,
            "result": "", "message": "", "created_at": now,
        }
    threading.Thread(target=_run_ocr_subtitle, args=(task_id, sid, rid, req.force, req.fps), daemon=True).start()
    return {"task_id": task_id}

@app.get("/api/ocr/active")
def ocr_active(sid: str = Depends(current_identity)):
    """查询当前用户是否有正在运行的 OCR 任务（服务端为准，刷新后恢复用）。

    前端刷新/重开页面后调用：若返回 running 任务，则据此高亮对应卡片按钮并轮询进度；
    这样即便 localStorage 被清或多标签之间状态不同步，也能以服务端内存态为准恢复。
    超过 2 小时的僵尸任务不返回。"""
    now = time.time()
    with tasks_lock:
        for _tid, _t in tasks.items():
            if (_t.get("type") == "ocr" and _t.get("owner") == sid
                    and _t.get("status") == "running"
                    and now - _t.get("created_at", 0) < 7200):
                return {"active": True, "task_id": _tid,
                        "resource_id": _t.get("resource_id"),
                        "progress": _t.get("progress", 0.0),
                        "message": _t.get("message", "")}
    return {"active": False}

@app.get("/api/task/{task_id}")
def get_task(task_id: str, sid: str = Depends(current_identity)):
    """通用后台任务状态查询（OCR 等），前端轮询此端点展示进度。

    数据来自内存 tasks 字典；服务重启后任务丢失则返回 404。
    仅任务 owner 可查询，避免跨账号窥探。"""
    with tasks_lock:
        t = tasks.get(task_id)
        t = dict(t) if t else None
    if not t:
        raise HTTPException(404, "任务不存在或已随服务重启丢失")
    if t.get("owner") and t.get("owner") != sid:
        raise HTTPException(403, "无权访问该任务")
    return t

def _run_ocr_subtitle(task_id, sid, rid, force, fps=1.0):
    """后台执行：前置检验 → 全量 OCR → 回填条目 subtitle 字段。"""
    def log(m):
        with tasks_lock:
            t = tasks.get(task_id)
            if t:
                t["log"].append(m)

    def setf(**kw):
        with tasks_lock:
            t = tasks.get(task_id)
            if t:
                t.update(kw)

    def setprog(pct, msg=""):
        """OCR 阶段进度回写：入参 0-100，task.progress 统一存 0-1（前端按 *100 显示）。"""
        with tasks_lock:
            t = tasks.get(task_id)
            if t:
                t["progress"] = round(pct / 100.0, 4)
                if msg:
                    t["message"] = msg

    try:
        # 重新取最新条目（避免拿到过期引用）；rid 匹配走 _rid_of_item，
        # 与 _find_resource 同口径，兼容只有 rel_path 的条目。
        cols = _sid_collections(sid)
        item = None
        for c in cols:
            for it in c.get("items", []):
                if _rid_of_item(it) == rid:
                    item = it
                    break
            if item:
                break
        if not item:
            setf(status="error", result="资源不存在")
            return
        rel = item.get("rel_path", "")
        vpath = os.path.join(DOWNLOADS, rel)
        if not os.path.isfile(vpath):
            setf(status="error", result="视频文件不存在")
            return
        out_dir = os.path.dirname(vpath)
        stem = os.path.splitext(os.path.basename(vpath))[0]

        # 前置检验：是否真有内嵌字幕
        detected, total, st = _detect_embedded_subtitle(vpath, log, model=OCR_MODEL,
                                                        progress_cb=setprog)
        log(f"[OCR预检] 在 {total} 帧中检测到 {detected} 帧含字幕")
        if detected == 0 and not force:
            setf(status="done", progress=1.0, result="no_subtitle",
                 message="未检测到内嵌字幕（若确认视频有字幕，可强制重试）")
            return

        # 全量 OCR（档位 fps：0.5/1/2）
        srt, txt, ost = _generate_ocr_subtitle(
            vpath, out_dir, log, title_hint=stem, model=OCR_MODEL, fps=fps,
            progress_cb=setprog)
        if ost != "ok" or not txt:
            setf(status="done", progress=1.0, result=ost or "empty",
                 message="未识别到硬字幕（可能确实无内嵌字幕）")
            return

        # 回填条目 subtitle 字段，使媒体库「有字幕」标识 / 字幕转文章 / 下载列表联动
        item["subtitle"] = txt
        item["subtitle_source"] = "ocr"
        _save_collections()
        setf(status="done", progress=1.0, result="ok", subtitle=txt,
             message="硬字幕识别完成")
    except Exception as e:
        setf(status="error", result=str(e)[:200])

def _read_subtitle_text(abs_path):
    """读取字幕/文本文件：去 BOM、按行 strip、丢掉空行（保留逐句一行的原始结构）。"""
    with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()
    raw = raw.lstrip("\ufeff")
    lines = [ln.strip() for ln in raw.splitlines()]
    return "\n".join(ln for ln in lines if ln)

_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")

def _normalize_for_match(s):
    """只保留中英文与数字，用于粗体句与原文的容错比对。

    英文统一小写：口语稿经 ASR 后英文大小写不稳定（ComfyUI / comfyUI），
    大小写差异不应算作「改写原文」，否则保真护栏会大量误报。
    """
    return re.sub(r"[^\u4e00-\u9fffA-Za-z0-9]+", "", (s or "").lower())

def _bold_fidelity(article, source):
    """护栏：检查所有 **粗体** 片段能否在原始字幕里找到。

    返回 (命中数, 总数, 未命中列表)。未命中通常意味着模型改写了原句或自行编造，
    前端会提示人工复核（不阻断，避免误伤跨行引用的正常情况）。
    """
    src = _normalize_for_match(source)
    spans = [m.group(1).strip() for m in _BOLD_RE.finditer(article or "")]
    bad = []
    for sp in spans:
        if not sp:
            continue
        if _normalize_for_match(sp) not in src:
            bad.append(sp)
    return len(spans) - len(bad), len(spans), bad

def _run_article_task(task_id):
    with _ARTICLE_TASKS_LOCK:
        cur = _ARTICLE_TASKS.get(task_id)
        cur = dict(cur) if cur else None
    if not cur:
        return

    def upd(**kw):
        with _ARTICLE_TASKS_LOCK:
            if task_id in _ARTICLE_TASKS:
                _ARTICLE_TASKS[task_id].update(kw)

    stop_tick = threading.Event()
    t0 = time.time()
    try:
        upd(status="running", progress=5, step="读取字幕文件…")
        text = _read_subtitle_text(cur["abs_path"])
        if not text.strip():
            upd(status="error", error="字幕文件内容为空", progress=100)
            return
        if len(text) > ARTICLE_MAX_SOURCE_CHARS:
            upd(status="error", progress=100,
                error=f"字幕过长（{len(text)} 字，单次上限 {ARTICLE_MAX_SOURCE_CHARS} 字）。"
                      f"请改用更短的单集，或先自行拆分该字幕文件。")
            return

        tpl = None
        tdata = _load_article_templates(cur["sid"])
        for x in tdata["builtin"] + tdata["templates"]:
            if x.get("id") == cur.get("template_id"):
                tpl = x
                break
        if tpl is None:
            allt = tdata["templates"] + tdata["builtin"]
            tpl = allt[0] if allt else None
        if not tpl:
            upd(status="error", error="没有可用的提示词模板", progress=100)
            return

        body_tpl = tpl.get("content") or ""
        if "{{content}}" in body_tpl:
            prompt = body_tpl.replace("{{content}}", text)
        else:
            prompt = body_tpl + "\n\n# 待处理文本\n" + text

        messages = [
            {"role": "system", "content": prompt},
            {"role": "user", "content": "请按上述要求，直接输出整理后的文章正文（Markdown 格式）。"},
        ]
        upd(progress=25, step=f"字幕 {len(text)} 字 · 正在调用模型…", source_len=len(text))

        def ticker():
            p = 25
            while not stop_tick.wait(1.5):
                p = min(92, p + 3)
                upd(progress=p, step=f"模型生成中… 已用时 {int(time.time() - t0)}s")

        threading.Thread(target=ticker, daemon=True).start()
        ok, result = _llm_chat(messages, model=cur.get("model") or LLM_MODEL)
        stop_tick.set()

        if not ok:
            upd(status="error", error=result, progress=100, step="生成失败",
                elapsed=round(time.time() - t0, 1))
            return

        article = result.strip()
        hit, total, bad = _bold_fidelity(article, text)
        _a_rid, _a_body = _rid_body_from_rel(cur.get("rel_path"))
        if _a_rid and _a_body:
            dest = os.path.join(_article_resource_md_dir(_a_rid, _a_body, cur["sid"]), task_id + ".md")
        else:
            dest = os.path.join(_article_art_dir(cur["sid"]), task_id + ".md")
        with open(dest, "w", encoding="utf-8") as f:
            f.write(article + "\n")
        base = os.path.splitext(cur.get("src_name") or "article")[0]
        upd(status="done", progress=100, content=article,
            step=f"完成 · 用时 {round(time.time() - t0, 1)}s",
            elapsed=round(time.time() - t0, 1),
            bold_total=total, bold_hit=hit, bold_bad=bad[:20],
            bold_rate=(round(hit * 100 / total) if total else None),
            md_path=dest, filename=base + ".md")
        # 持久化文章索引（来源字幕 rel_path 等）：使「媒体库卡片关联文章」在重启后仍有效
        try:
            with _ARTICLE_TASKS_LOCK:
                idx = _load_article_index(cur["sid"])
                # C 方案：显式绑定 resource_id/body_key8（消除 rel_path 反查脆弱）+ owner/模板名标记
                _a_tpls = _load_article_templates(cur["sid"])
                _a_tname = ""
                for _t in _a_tpls.get("builtin", []) + _a_tpls.get("templates", []):
                    if _t.get("id") == cur.get("template_id"):
                        _a_tname = _t.get("name", "")
                        break
                idx[task_id] = {
                    "rel_path": cur.get("rel_path"), "src_name": cur.get("src_name"),
                    "filename": base + ".md", "template_id": cur.get("template_id"),
                    "template_name": _a_tname, "model": cur.get("model"),
                    "resource_id": _a_rid, "body_key8": _a_body,
                    "owner": user_hash(cur["sid"]), "created_at": cur.get("created_at"),
                    "bold_rate": (round(hit * 100 / total) if total else None),
                    "bold_hit": hit, "bold_total": total,
                    "bold_bad": bad[:20],
                    "elapsed": round(time.time() - t0, 1), "status": "done",
                }
                _save_article_index(cur["sid"], idx)
        except Exception as _ie:
            print(f"[article] index save failed: {_ie}", flush=True)
    except Exception as e:
        stop_tick.set()
        upd(status="error", error=f"{type(e).__name__}: {e}", progress=100)

def _existing_article_rel_paths(sid):
    """该用户「已生成过文章」的来源字幕 rel_path 集合。

    取并集：磁盘索引 index.json（重启后仍在）+ 内存任务里已完成的。
    批量生成默认据此跳过，避免对同一份字幕重复消耗模型时间。
    """
    rels = set()
    try:
        for meta in _load_article_index(sid).values():
            rp = (meta or {}).get("rel_path")
            if rp:
                rels.add(rp)
    except Exception:
        pass
    with _ARTICLE_TASKS_LOCK:
        for t in _ARTICLE_TASKS.values():
            if t.get("sid") == sid and t.get("status") == "done" and t.get("rel_path"):
                rels.add(t["rel_path"])
    return rels

def _run_article_batch(batch_id):
    """批量串行 worker：逐篇复用 _run_article_task。

    _run_article_task 是同步阻塞的（内部同步调 LLM），所以顺序调用天然构成队列，
    不需要额外并发控制；再配合「一篇跑完才起下一篇」，本地模型始终只承载 1 路请求。
    """
    def bupd(**kw):
        with _ARTICLE_BATCH_LOCK:
            b = _ARTICLE_BATCHES.get(batch_id)
            if b:
                b.update(kw)

    with _ARTICLE_BATCH_LOCK:
        b = _ARTICLE_BATCHES.get(batch_id)
        if not b:
            return
        items, sid = b["items"], b["sid"]
        tpl_id, model = b["template_id"], b["model"]

    done = failed = 0
    bupd(status="running", started_at=time.time())
    for i, it in enumerate(items):
        if it.get("status") != "queued":
            continue
        with _ARTICLE_BATCH_LOCK:
            cur = _ARTICLE_BATCHES.get(batch_id)
            if not cur or cur.get("cancel"):
                bupd(status="cancelled", current=None, current_index=-1,
                     step=f"已取消（已完成 {done} 篇）", finished_at=time.time())
                return
        it["status"] = "running"
        bupd(current=it.get("rel_path"), current_index=i,
             step=f"正在生成 {i + 1}/{len(items)}：{it.get('label') or it.get('rel_path')}")

        task_id = uuid.uuid4().hex[:16]
        with _ARTICLE_TASKS_LOCK:
            _ARTICLE_TASKS[task_id] = {
                "id": task_id, "sid": sid, "rel_path": it["rel_path"],
                "abs_path": os.path.join(DOWNLOADS, it["rel_path"]),
                "src_name": os.path.basename(it["rel_path"]),
                "template_id": tpl_id, "model": model,
                "status": "queued", "progress": 0, "step": "排队中…",
                "content": "", "error": "", "created_at": time.time(),
            }
        _run_article_task(task_id)   # ★ 同步：跑完这篇才继续下一篇
        with _ARTICLE_TASKS_LOCK:
            res = dict(_ARTICLE_TASKS.get(task_id) or {})

        it["task_id"] = task_id
        it["filename"] = res.get("filename") or ""
        if res.get("status") == "done":
            it["status"] = "done"
            it["bold_rate"] = res.get("bold_rate")
            done += 1
        else:
            it["status"] = "error"
            it["error"] = res.get("error") or "生成失败"
            failed += 1
        bupd(done=done, failed=failed, step=f"已完成 {done + failed}/{len(items)}")

    # 若「停止」是在最后一篇生成期间点的，循环里没机会检查 → 这里补一次，避免误报成正常完成
    with _ARTICLE_BATCH_LOCK:
        cur = _ARTICLE_BATCHES.get(batch_id)
        cancelled = bool(cur and cur.get("cancel"))
    if cancelled:
        bupd(status="cancelled", current=None, current_index=-1, done=done, failed=failed,
             step=f"已取消（已完成 {done} 篇）", finished_at=time.time())
        return
    bupd(status="done", current=None, current_index=-1, done=done, failed=failed,
         step=f"全部完成：成功 {done} 篇" + (f"，失败 {failed} 篇" if failed else ""),
         finished_at=time.time())

class ArticleGenReq(BaseModel):
    rel_path: str            # 字幕文件相对路径（必须在自己的 users/{hash}/ 下）
    template_id: str = ""
    model: str = ""

class ArticleBatchGenReq(BaseModel):
    rel_paths: list = []     # 字幕相对路径列表（勾选的视频各自绑定的字幕）
    template_id: str = ""
    model: str = ""
    skip_existing: bool = True   # 已有文章的字幕默认跳过

class ArticleTplSaveReq(BaseModel):
    id: str = ""
    name: str = ""
    content: str = ""

class ArticleCheckReq(BaseModel):
    rel_path: str
    content: str

class ArticleRenameReq(BaseModel):
    name: str = ""

@app.get("/api/article/models")
def article_models(sid: str = Depends(current_identity)):
    """可用模型列表（透传 LM Studio /v1/models），供前端下拉。"""
    return {"ok": True, "base_url": LLM_BASE_URL, "default": LLM_MODEL, "models": _llm_models()}

@app.get("/api/article/templates")
def article_tpl_list(sid: str = Depends(current_identity)):
    """当前用户的模板：内置（只读）+ 自定义。"""
    t = _load_article_templates(sid)
    out = [{"id": x.get("id"), "name": x.get("name"), "builtin": True} for x in t["builtin"]]
    out += [{"id": x.get("id"), "name": x.get("name"), "builtin": False} for x in t["templates"]]
    return {"ok": True, "templates": out}

@app.get("/api/article/templates/{tid}")
def article_tpl_get(tid: str, sid: str = Depends(current_identity)):
    t = _load_article_templates(sid)
    for x in t["builtin"] + t["templates"]:
        if x.get("id") == tid:
            return {"ok": True, "template": x}
    raise HTTPException(404, "模板不存在")

@app.put("/api/article/templates")
def article_tpl_save(req: ArticleTplSaveReq, sid: str = Depends(current_identity)):
    """新建（id 为空）或覆盖保存「当前用户」的模板。

    若 id 命中内置模板（用户编辑内置后点保存），则「另存为用户副本」，不覆盖内置只读项。
    ⚠️ 不可在持 _templates_lock 时调用 _save_article_templates（非重入锁会自死锁）；
       内存修改在锁内完成，落盘在锁外进行。
    """
    name = (req.name or "").strip() or "未命名模板"
    content = req.content or ""
    if not content.strip():
        raise HTTPException(400, "模板内容不能为空")
    BUILTIN_IDS = {DEFAULT_TEMPLATE_ID}
    tid = (req.id or "").strip()
    with _templates_lock:
        data = _templates_cache or _read_or_init_templates()
        uh = user_hash(sid)
        bucket = data.setdefault("users", {}).setdefault(uh, {"templates": []})
        tpls = bucket.setdefault("templates", [])
        found = None
        if tid and tid not in BUILTIN_IDS:
            for x in tpls:
                if x.get("id") == tid:
                    found = x
                    break
            if found is None:
                raise HTTPException(404, "模板不存在")
        if found:
            found["name"] = name
            found["content"] = content
            found["updated_at"] = time.time()
            result = {"ok": True, "template": found, "created": False}
        else:
            new_id = uuid.uuid4().hex[:8]
            tpl = {"id": new_id, "name": name, "content": content, "builtin": False, "updated_at": time.time()}
            tpls.append(tpl)
            result = {"ok": True, "template": tpl, "created": True}
    _save_article_templates()   # 锁已释放，安全落盘
    return result

@app.delete("/api/article/templates/{tid}")
def article_tpl_delete(tid: str, sid: str = Depends(current_identity)):
    """删除「当前用户」的自定义模板；内置模板不可删。"""
    if tid in {DEFAULT_TEMPLATE_ID}:
        raise HTTPException(400, "内置模板不可删除（编辑后保存会另存为你的副本）")
    with _templates_lock:
        data = _templates_cache or _read_or_init_templates()
        uh = user_hash(sid)
        bucket = data.get("users", {}).get(uh, {})
        tpls = bucket.get("templates", [])
        if not tpls:
            raise HTTPException(400, "你还没有自定义模板")
        idx = next((i for i, x in enumerate(tpls) if x.get("id") == tid), None)
        if idx is None:
            raise HTTPException(404, "模板不存在")
        tpls.pop(idx)
    _save_article_templates()   # 锁已释放，安全落盘
    return {"ok": True}

def _shared_subtitle_accepted(sid, rel):
    """若 sid 已接受该字幕所属资源的共享且令牌仍有效，返回 (owner, rid)，否则 (None, None)。

    用于放开 article_generate / article_check 对「自己目录」的硬限制：被共享方也能基于
    owner 字幕生成文章（文章落到接收方自己的 _articles/users/<sid>/ 目录，互不干扰）。
    仅当 rel 不属于 sid 自身目录时才查共享；属于自身目录直接走原逻辑。"""
    rel_norm = (rel or "").replace("\\", "/").strip().lstrip("/")
    if not rel_norm or rel_norm.startswith(user_scope(sid) + "/"):
        return None, None
    data = _load_shares()
    accepted = (data.get("accepted") or {}).get(sid) or {}
    if not accepted:
        return None, None
    tokens = data.get("tokens") or {}
    now = time.time()
    for token, _meta in accepted.items():
        tok = tokens.get(token)
        if not tok or tok.get("revoked"):
            continue
        exp = tok.get("expires_at")
        if exp is not None and exp < now:
            continue
        owner = tok.get("owner")
        rid = tok.get("resource_id")
        if not owner or not rid:
            continue
        _item, paths = _find_resource(owner, rid)
        if not paths:
            continue
        if rel_norm in paths:
            return owner, rid
    return None, None

@app.post("/api/article/generate")
def article_generate(req: ArticleGenReq, sid: str = Depends(current_identity)):
    """按字幕文件启动一次文章生成（后台线程，前端轮询 /api/article/task/{id}）。"""
    rel = (req.rel_path or "").strip().replace("\\", "/").lstrip("/")
    if not rel:
        raise HTTPException(400, "缺少字幕文件路径")
    # 安全：池化资源（resources/<rid>/）且 sid 拥有该资源 → 放行；被共享且在有效期内的资源亦放行
    _parts = rel.split("/")
    if _parts[0] == "resources" and len(_parts) >= 2 and _owner_has_active_ref(sid, _parts[1]):
        pass
    elif not rel.startswith(user_scope(sid) + "/"):
        owner, _rid = _shared_subtitle_accepted(sid, rel)
        if not owner:
            raise HTTPException(403, "只能对自己目录下的字幕生成文章")
    abs_path = os.path.join(DOWNLOADS, rel)
    if not os.path.isfile(abs_path):
        raise HTTPException(404, "字幕文件不存在（可能已被删除）")
    if os.path.splitext(abs_path)[1].lower() not in (".txt", ".srt", ".vtt", ".ass", ".lrc"):
        raise HTTPException(400, "仅支持字幕类文本文件（.txt/.srt/.vtt/.ass/.lrc）")
    if not LLM_BASE_URL:
        raise HTTPException(500, "服务端未配置模型地址（llm_base_url）")
    # 模板显式校验：不再静默回退默认模板（避免「界面没选模板、实际却用了内置模板」的错位）
    tpl_id = (req.template_id or "").strip()
    if not tpl_id:
        raise HTTPException(400, "未指定提示词模板")
    tdata = _load_article_templates(sid)
    if not any((t or {}).get("id") == tpl_id for t in tdata["builtin"] + tdata["templates"]):
        raise HTTPException(404, "模板不存在或不属于当前用户")

    task_id = uuid.uuid4().hex[:16]
    with _ARTICLE_TASKS_LOCK:
        _ARTICLE_TASKS[task_id] = {
            "id": task_id, "sid": sid, "rel_path": rel, "abs_path": abs_path,
            "src_name": os.path.basename(rel),
            "template_id": tpl_id,
            "model": (req.model or "").strip() or LLM_MODEL,
            "status": "queued", "progress": 0, "step": "排队中…",
            "content": "", "error": "", "created_at": time.time(),
        }
    threading.Thread(target=_run_article_task, args=(task_id,), daemon=True).start()
    return {"ok": True, "task_id": task_id}

@app.post("/api/article/generate-batch")
def article_generate_batch(req: ArticleBatchGenReq, sid: str = Depends(current_identity)):
    """批量：对勾选的多个字幕「串行」生成文章（后台队列，前端轮询 /api/article/batch/{id}）。

    逐项先做准入过滤，不合格的项以 status=skipped + note 原样回给前端（让用户看到为什么没生成）：
    不在自己目录 / 不是字幕类文件 / 文件不存在 / 已有文章（skip_existing）。
    """
    rels = [(_r or "").strip().replace("\\", "/").lstrip("/") for _r in (req.rel_paths or [])]
    rels = [r for r in rels if r]
    if not rels:
        raise HTTPException(400, "没有选中任何视频")
    if not LLM_BASE_URL:
        raise HTTPException(500, "服务端未配置模型地址（llm_base_url）")
    tpl_id = (req.template_id or "").strip()
    if not tpl_id:
        raise HTTPException(400, "未指定提示词模板")
    tdata = _load_article_templates(sid)
    if not any((t or {}).get("id") == tpl_id for t in tdata["builtin"] + tdata["templates"]):
        raise HTTPException(404, "模板不存在或不属于当前用户")

    have = _existing_article_rel_paths(sid) if req.skip_existing else set()
    scope = user_scope(sid) + "/"
    items, seen = [], set()
    for r in rels:
        if r in seen:
            continue
        seen.add(r)
        row = {"rel_path": r, "label": os.path.basename(r),
               "status": "queued", "note": "", "error": "", "task_id": "", "filename": ""}
        ext = os.path.splitext(r)[1].lower()
        _parts = r.split("/")
        if not (r.startswith(scope)
                or (_parts[0] == "resources" and len(_parts) >= 2 and _owner_has_active_ref(sid, _parts[1]))):
            row.update(status="skipped", note="不在你的目录下")
        elif ext not in (".txt", ".srt", ".vtt", ".ass", ".lrc"):
            row.update(status="skipped", note="不是字幕文件")
        elif not os.path.isfile(os.path.join(DOWNLOADS, r)):
            row.update(status="skipped", note="字幕文件不存在")
        elif r in have:
            row.update(status="skipped", note="已有文章")
        items.append(row)

    queued = [x for x in items if x["status"] == "queued"]
    if not queued:
        return {"ok": True, "batch_id": "", "total": len(items), "queued": 0,
                "skipped": len(items), "items": items,
                "message": "选中的视频都已有文章（或没有可用字幕），无需生成"}

    # ★ 关键：先拷一份「创建时刻」的快照再启线程。
    # worker 会立刻改写 items（queued→running），若不拷贝，HTTP 响应序列化时会把
    # 「准入结果」读成「实时状态」，前端首屏就会把正在生成的项误显示成跳过。
    snapshot = [dict(x) for x in items]
    batch_id = uuid.uuid4().hex[:16]
    with _ARTICLE_BATCH_LOCK:
        _ARTICLE_BATCHES[batch_id] = {
            "id": batch_id, "sid": sid, "template_id": tpl_id,
            "model": (req.model or "").strip() or LLM_MODEL,
            "status": "queued", "step": "排队中…",
            "items": items, "done": 0, "failed": 0,
            "current": None, "current_index": -1,
            "created_at": time.time(), "cancel": False,
        }
    threading.Thread(target=_run_article_batch, args=(batch_id,), daemon=True).start()
    return {"ok": True, "batch_id": batch_id, "total": len(items),
            "queued": len(queued), "skipped": len(items) - len(queued), "items": snapshot}

@app.get("/api/article/batch/{batch_id}")
def article_batch(batch_id: str, sid: str = Depends(current_identity)):
    """批量生成进度（前端每 1.5s 轮询）。"""
    with _ARTICLE_BATCH_LOCK:
        b = _ARTICLE_BATCHES.get(batch_id)
        if not b:
            raise HTTPException(404, "批次不存在或已随服务重启丢失")
        if b.get("sid") != sid:
            raise HTTPException(403, "无权访问该批次")
        out = {k: v for k, v in b.items() if k not in ("sid", "cancel")}
        out["items"] = [dict(x) for x in b["items"]]
    out["ok"] = True
    return out

@app.post("/api/article/batch/{batch_id}/cancel")
def article_batch_cancel(batch_id: str, sid: str = Depends(current_identity)):
    """停止批量：worker 在「下一篇开始前」检查标记，当前正在生成的那篇不打断。"""
    with _ARTICLE_BATCH_LOCK:
        b = _ARTICLE_BATCHES.get(batch_id)
        if not b:
            raise HTTPException(404, "批次不存在或已随服务重启丢失")
        if b.get("sid") != sid:
            raise HTTPException(403, "无权访问该批次")
        b["cancel"] = True
    return {"ok": True}

@app.get("/api/article/task/{task_id}")
def article_task(task_id: str, sid: str = Depends(current_identity)):
    with _ARTICLE_TASKS_LOCK:
        t = _ARTICLE_TASKS.get(task_id)
        t = dict(t) if t else None
    if not t:
        raise HTTPException(404, "任务不存在或已随服务重启丢失")
    if t.get("sid") != sid:
        raise HTTPException(403, "无权访问该任务")
    t.pop("abs_path", None)
    t.pop("sid", None)
    return t

@app.get("/api/article/list")
def article_list(sid: str = Depends(current_identity)):
    """当前用户已生成的文章（磁盘为准，服务重启不丢）。"""
    with _ARTICLE_TASKS_LOCK:
        mem = {k: dict(v) for k, v in _ARTICLE_TASKS.items() if v.get("sid") == sid}
    idx = _load_article_index(sid)
    items = []
    # 内存态（生成中 / 刚完成尚未落 index）按 mem 优先
    for tid, t in mem.items():
        _r, _b = _rid_body_from_rel(t.get("rel_path"))
        if not (_r and _b):
            continue
        p = os.path.join(_article_resource_md_dir(_r, _b, sid), tid + ".md")
        if not os.path.isfile(p):
            continue
        st = os.stat(p)
        items.append({
            "task_id": tid,
            "filename": (t.get("filename") or (tid + ".md")),
            "src_name": t.get("src_name") or "",
            "rel_path": t.get("rel_path") or "",
            "size": st.st_size,
            "created_at": t.get("created_at") or st.st_mtime,
            "bold_rate": t.get("bold_rate"),
            "in_memory": True,
        })
    # 持久化态（已完成且已写 index，且未出现在 mem）
    for stem, meta in idx.items():
        if stem in mem:
            continue
        _r, _b = meta.get("resource_id"), meta.get("body_key8")
        if not (_r and _b):
            continue
        p = os.path.join(_article_resource_md_dir(_r, _b, sid), stem + ".md")
        if not os.path.isfile(p):
            continue
        st = os.stat(p)
        items.append({
            "task_id": stem,
            "filename": meta.get("filename") or (stem + ".md"),
            "src_name": meta.get("src_name") or "",
            "rel_path": meta.get("rel_path") or "",
            "size": st.st_size,
            "created_at": meta.get("created_at") or st.st_mtime,
            "bold_rate": meta.get("bold_rate"),
            "in_memory": False,
        })
    items.sort(key=lambda x: x["created_at"], reverse=True)
    # 显示名去重：同一来源字幕多次生成 → filename 相同，列表里会重名。
    # 仅计算一个 display_name（追加 (2)/(3)…）用于前端展示，不动 filename（下载/删除/重命名均按 task_id）。
    _name_counter = {}
    for it in items:
        raw = it.get("filename") or (it["task_id"] + ".md")
        _base, _ext = os.path.splitext(raw)
        if not _ext:
            _ext = ".md"
        _name_counter[raw] = _name_counter.get(raw, 0) + 1
        n = _name_counter[raw]
        it["display_name"] = raw if n == 1 else f"{_base} ({n}){_ext}"
    return {"ok": True, "items": items}

@app.get("/api/article/meta/{task_id}")
def article_meta(task_id: str, sid: str = Depends(current_identity)):
    """文章「粗体保真」元数据（命中率 + 未命中片段），供文章预览时显示未命中提示。"""
    stem = _article_stem(task_id)
    if not stem:
        raise HTTPException(400, "非法任务号")
    return {"ok": True, **_article_bold_for(sid, stem)}

@app.get("/api/article/file/{task_id}")
def article_file(task_id: str, sid: str = Depends(current_identity)):
    stem = _article_stem(task_id)
    if not stem:
        raise HTTPException(400, "非法任务号")
    meta = dict(_load_article_index(sid).get(stem) or _ARTICLE_TASKS.get(stem) or {})
    _r, _b = meta.get("resource_id"), meta.get("body_key8")
    if not (_r and _b):
        raise HTTPException(404, "文章不存在或缺少资源定位信息")
    p = os.path.join(_article_resource_md_dir(_r, _b, sid), stem + ".md")
    if not os.path.isfile(p):
        raise HTTPException(404, "文章不存在")
    with _ARTICLE_TASKS_LOCK:
        meta = dict(_ARTICLE_TASKS.get(stem) or {})
    return FileResponse(p, media_type="text/markdown; charset=utf-8",
                        filename=meta.get("filename") or (stem + ".md"))

@app.delete("/api/article/file/{task_id}")
def article_file_delete(task_id: str, sid: str = Depends(current_identity)):
    """删除「当前用户」已生成的文章（.md 物理文件）。"""
    stem = _article_stem(task_id)
    if not stem:
        raise HTTPException(400, "非法任务号")
    meta = _load_article_index(sid).get(stem)
    _r, _b = (meta or {}).get("resource_id"), (meta or {}).get("body_key8")
    if not (_r and _b):
        raise HTTPException(404, "文章不存在或缺少资源定位信息")
    p = os.path.join(_article_resource_md_dir(_r, _b, sid), stem + ".md")
    if not os.path.isfile(p):
        raise HTTPException(404, "文章不存在")
    try:
        os.remove(p)
    except OSError as e:
        raise HTTPException(500, f"删除失败：{e}")
    with _ARTICLE_TASKS_LOCK:
        _ARTICLE_TASKS.pop(stem, None)
        idx = _load_article_index(sid)
        if stem in idx:
            idx.pop(stem, None)
            _save_article_index(sid, idx)
    return {"ok": True}

@app.put("/api/article/file/{task_id}")
def article_file_rename(task_id: str, req: ArticleRenameReq, sid: str = Depends(current_identity)):
    """重命名已生成的文章（文件名即任务号，重命名后旧任务号失效）。

    名称允许中文等任意非危险字符，仅去除路径分隔与非法文件名字符，避免「中文名被吞成 article」。
    """
    stem = _article_stem(task_id)
    if not stem:
        raise HTTPException(400, "非法任务号")
    raw = (req.name or "").strip()
    if not raw:
        raise HTTPException(400, "新文件名不能为空")
    # 仅剔除路径分隔与文件系统非法字符，保留中文等；为空则回退 article
    clean = re.sub(r"[/\\:*?\"<>|\x00-\x1f]", "", raw).strip()[:120] or "article"
    meta = _load_article_index(sid).get(stem)
    _r, _b = (meta or {}).get("resource_id"), (meta or {}).get("body_key8")
    if not (_r and _b):
        raise HTTPException(404, "文章不存在或缺少资源定位信息")
    d = _article_resource_md_dir(_r, _b, sid)
    oldp = os.path.join(d, stem + ".md")
    if not os.path.isfile(oldp):
        raise HTTPException(404, "文章不存在")
    newp = os.path.join(d, clean + ".md")
    if os.path.abspath(newp) != os.path.abspath(oldp) and os.path.isfile(newp):
        raise HTTPException(409, "已存在同名文章，请换个名字")
    try:
        os.rename(oldp, newp)
    except OSError as e:
        raise HTTPException(500, f"重命名失败：{e}")
    with _ARTICLE_TASKS_LOCK:
        t = _ARTICLE_TASKS.get(stem)
        if t:
            t["filename"] = clean + ".md"
            t["id"] = clean
        # 同步持久化索引：key 由旧 stem 改为新 stem（文章身份 = 文件名 stem）
        idx = _load_article_index(sid)
        old_meta = idx.pop(stem, None)
        if old_meta is None and t:
            old_meta = {"rel_path": t.get("rel_path"), "src_name": t.get("src_name"),
                        "template_id": t.get("template_id"), "model": t.get("model"),
                        "created_at": t.get("created_at"), "bold_rate": t.get("bold_rate"),
                        "bold_hit": t.get("bold_hit"), "bold_total": t.get("bold_total"),
                        "elapsed": t.get("elapsed"), "status": t.get("status")}
        if old_meta is not None:
            old_meta["filename"] = clean + ".md"
            idx[clean] = old_meta
            _save_article_index(sid, idx)
    return {"ok": True, "task_id": clean, "filename": clean + ".md"}

@app.post("/api/article/check")
def article_check(req: ArticleCheckReq, sid: str = Depends(current_identity)):
    """对（可能被人工编辑过的）文章重新做粗体保真校验。"""
    rel = (req.rel_path or "").strip().replace("\\", "/").lstrip("/")
    _parts = rel.split("/")
    if _parts[0] == "resources" and len(_parts) >= 2 and _owner_has_active_ref(sid, _parts[1]):
        pass
    elif not rel.startswith(user_scope(sid) + "/"):
        owner, _rid = _shared_subtitle_accepted(sid, rel)
        if not owner:
            raise HTTPException(403, "只能校验自己目录下的字幕")
    abs_path = os.path.join(DOWNLOADS, rel)
    if not os.path.isfile(abs_path):
        raise HTTPException(404, "字幕文件不存在")
    src = _read_subtitle_text(abs_path)
    hit, total, bad = _bold_fidelity(req.content or "", src)
    return {"ok": True, "bold_total": total, "bold_hit": hit, "bold_bad": bad[:20],
            "bold_rate": (round(hit * 100 / total) if total else None)}

# ===================== RM 新增：ingest / upload / import-dir =====================

def _sha256_of_file(fp):
    """流式计算文件 sha256（避免大文件占内存）。"""
    h = hashlib.sha256()
    with open(fp, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# 资源池 body_key8 派生（O3 治本，2026-10-20）：
# 历史上 body_key8 = sha256(文件名|大小)[:8] —— 与内容无关，导致「同内容不同文件名」落两份。
# 现改为与文件内容绑定：rid 取内容哈希 [:15]，body_key8 取同一哈希的 [16:24] 窗口
# （与 rid 前缀不重叠，仍为纯内容派生）。保证「同内容即同 body_key8」，入池即可去重。
# 该公式在 app.py / inbox_watcher.py / scripts/migrate_body_key8.py 三处须保持一致。
_BODY_KEY8_WIN = slice(16, 24)


def _body_key8_from_hash(h: str) -> str:
    """由内容 sha256 十六进制串派生 body_key8（纯内容派生，与文件名/大小无关）。"""
    return h[_BODY_KEY8_WIN]


def _find_identical_media(pool_dir, content_sha256):
    """在 pool_dir 内查找与 content_sha256 完全相同内容的主媒体文件绝对路径；无则 None。

    用于内容级去重（O3 治本）：即使文件名不同，只要字节完全一致就复用已有文件，
    不再存第二份。"""
    if not content_sha256 or not os.path.isdir(pool_dir):
        return None
    for fn in os.listdir(pool_dir):
        if not fn.lower().endswith(MAIN_EXT):
            continue
        p = os.path.join(pool_dir, fn)
        if os.path.isfile(p) and _sha256_of_file(p) == content_sha256:
            return p
    return None


def _pick_main_media_in_dir(d, prefer_html=False):
    """返回目录内主文件绝对路径（无则 None）。用于回收站还原定位主文件。
    prefer_html=True（公众号文章场景）：优先返回 .html 正文文件，避免退化成目录路径导致 serve 404（P0-4）。
    默认保持原行为：挑体积最大的媒体文件（视频/音频），对视频零副作用。"""
    if not os.path.isdir(d):
        return None
    if prefer_html:
        for fn in os.listdir(d):
            if fn.lower().endswith(".html") and os.path.isfile(os.path.join(d, fn)):
                return os.path.join(d, fn)
    best, best_sz = None, -1
    for fn in os.listdir(d):
        if fn.lower().endswith(MAIN_EXT) and os.path.isfile(os.path.join(d, fn)):
            sz = os.path.getsize(os.path.join(d, fn))
            if sz > best_sz:
                best_sz, best = sz, os.path.join(d, fn)
    return best


def _recycle_unreferenced_body_dirs(rid, keep_body_key8):
    """R2（换内容回收，2026-10-21）：扫描 resources/<rid>/ 下所有 body_key8 子目录，
    凡不被任何活跃（非 __trash__）条目 rel_path 引用的子目录，登记为回收站条目
    （物理保留，绝不直接删；resource_id 仍用真实 rid + 附加 body_key8 字段以便精确还原/清理）。

    背景：换内容 = 同 rid 多 body_key8 子目录，旧子目录因 rid 仍被新条目引用而 rid 级回收站
    （count_active_refs(rid)==0 才触发）永不触发，旧文件成孤儿。此处补 (rid, body_key8) 级判定，
    让旧版本进回收站可恢复，而非靠人扫或静默丢弃。"""
    if not rid or not keep_body_key8:
        return
    res_rid_dir = os.path.join(RESOURCES_DIR, rid)
    if not os.path.isdir(res_rid_dir):
        return
    # 收集所有活跃条目引用的 body_key8 子目录（rel_path 形如 resources/<rid>/<body_key8>/...）
    referenced = set()
    data = _load_collections()
    for owner, v in data.items():
        for c in v.get("collections", []):
            if c.get("id") == "__trash__":
                continue
            for it in c.get("items", []):
                rp = (it.get("rel_path") or "").replace("\\", "/")
                if rp.startswith("resources/" + rid + "/"):
                    parts = rp.split("/")
                    if len(parts) >= 3:
                        referenced.add(parts[2])
    for sub in sorted(os.listdir(res_rid_dir)):
        sub_dir = os.path.join(res_rid_dir, sub)
        if not os.path.isdir(sub_dir):
            continue
        if sub == keep_body_key8 or sub in referenced:
            continue
        # 无引用 -> 旧版本，登记回收站（物理保留，绝不直接删）
        # P0-4：prefer_html=True 让文章正文 .html 当主文件；视频目录无 .html，行为不变。
        main = _pick_main_media_in_dir(sub_dir, prefer_html=True)
        is_article = bool(main and main.lower().endswith(".html"))
        rel = (os.path.relpath(main, DOWNLOADS).replace(os.sep, "/")
               if main else ("resources/" + rid + "/" + sub + "/"))
        # 构建可恢复快照：扫描子目录里的封面/字幕，使 restore 后能还原可播放条目
        cover = next((f for f in os.listdir(sub_dir)
                      if f.lower().endswith((".jpg", ".jpeg", ".png", ".webp"))), "") or ""
        sub_file = (next((f for f in os.listdir(sub_dir) if f.lower().endswith(".txt")), "") or
                    next((f for f in os.listdir(sub_dir) if f.lower().endswith(".srt")), "") or "")
        snap = {
            "rel_path": rel,
            "title": (rid + " (旧内容 " + sub + ")"),
            "resource_id": rid,
            "body_key8": sub,
            "vid": "",
            "seq": "",
            "duration": None,
            "cover": cover,
            "subtitle": sub_file,
            "subtitle_srt": "",
            "subtitle_source": "official" if sub_file else "",
            "added_at": time.time(),
        }
        # 文章旧版：补全 source_type/images，使 restore 后仍是「文章」卡片且正文图片可见（P0-2/P0-4 配套）
        if is_article:
            snap["source_type"] = "wechat_article"
            snap["media_type"] = "article"
            snap["images"] = [os.path.relpath(os.path.join(sub_dir, f), DOWNLOADS).replace(os.sep, "/")
                              for f in sorted(os.listdir(sub_dir)) if f.lower().endswith(IMG_EXTS)]
        ensure_trash_entry(rid, snap["title"], "ingest(R2)", rel_path=rel,
                           item=snap, body_key8=sub)


def _ingest_into_pool(owner, rid, body_key8, main_abs, extras_abs, title, target_cid="default",
                      vid="", seq="", subtitle_source="", cover="", content_sha256="",
                      target_name="", source_type="video", url="",
                      published_at="", content_type="", keep_versions=False):
    """统一入池 + 登记合集引用（ingest / upload / import-dir / watcher 共用，见 RM-实施指引 §2）。

    去重（O3 治本，2026-10-20）：body_key8 已改为「文件内容哈希派生」，配合此处的内容级去重，
    保证「同内容（无论文件名/大小）只存一份」：
      - resources/<rid>/<body_key8>/ 内若已有与 content_sha256 完全相同的主媒体 -> dedup_hit=True，
        复用已有文件、丢弃刚迁入的重复副本（附加物字幕/封面仍迁入）；
      - 否则把 staging 主文件 + 附加物迁入池。
    content_sha256 由调用方传入（调用方本就为算 rid/body_key8 哈希过文件，避免重复 I/O）。
    始终 _add_to_collection 登记引用（删除引用归零即入 __trash__，与资源池同保护）。
    R1（2026-10-21）：附加物支持 txt + srt 等多字幕，txt 优先绑 entry["subtitle"]（match_subtitle
        契约仅认 _字幕.txt），srt 等作为增强以 entry["subtitle_srt"] 记录池内相对路径。
    R2（2026-10-21）：末尾扫同 rid 下无引用的旧 body_key8 子目录 -> 入回收站（物理保留）。
    返回 (resource_id, dedup_hit, rel_path, replaced_rel_path)。
    """
    pool_dir = _pool_dir(rid, body_key8)
    existing = _find_identical_media(pool_dir, content_sha256)
    dedup_hit = bool(existing)
    new_main, new_extras = _move_staged_to_pool(main_abs, list(extras_abs or []), rid, body_key8)
    if not new_main and not existing:
        raise HTTPException(400, "主媒体文件不存在或迁入资源池失败")
    if existing:
        # 复用池内已有内容文件，丢弃刚迁入的重复副本（O3 治本：同内容不同文件名亦只存一份）
        try:
            if os.path.abspath(new_main) != os.path.abspath(existing):
                os.remove(new_main)
        except OSError:
            pass
        rel_main = os.path.relpath(existing, DOWNLOADS).replace(os.sep, "/")
    else:
        rel_main = os.path.relpath(new_main, DOWNLOADS).replace(os.sep, "/")
    entry = {
        "rel_path": rel_main,
        "title": (title or _title_from_filename(os.path.basename(main_abs))),
        "resource_id": rid,
        "body_key8": body_key8,
        "media_type": media_type_of(main_abs),  # 前瞻埋点（2026-10-22）：video/audio/text/image
        "source_type": source_type,  # 资源大类（默认 video）；公众号图文为 wechat_article
        "url": url,                  # 公众号文章永久直链（其它资源为空）
        "vid": vid,
        "seq": seq,
        "duration": None,
        "cover": "",
        "subtitle": "",
        "meta": "",                       # O3 解耦的 meta.json 衍生物（池内相对路径）
        "added_at": time.time(),
    }
    # 按扩展名归类附加物（R1，2026-10-21）：
    #   - 字幕：RM 的 match_subtitle 仅认 _字幕.txt 后缀，故 txt 优先绑定到 entry["subtitle"]；
    #     srt/vtt/ass/xml 作为「可选增强」保留进资源池（已被 _move_staged_to_pool 物理迁移），
    #     并以 entry["subtitle_srt"] 记录其池内相对路径（前端按需使用，非 match_subtitle 契约）。
    #   - 封面：.jpg/.jpeg/.png/.webp 作为候选（与显式 cover 字段二选一）。
    # 向后兼容 watcher 三件套 / 老 import-dir（仅字幕） / /api/ingest（subtitle_path+cover）。
    _extras = list(new_extras or [])
    _txt = next((e for e in _extras if e.lower().endswith(".txt")), "")
    _srt = next((e for e in _extras if e.lower().endswith(".srt")), "")
    _other_sub = next((e for e in _extras if e.lower().endswith((".vtt", ".ass", ".xml"))), "")
    cover_candidate = next((e for e in _extras if e.lower().endswith(IMG_EXTS)), "")
    # txt 优先（match_subtitle 契约）；无 txt 时退化用其它字幕格式，保证有字幕可显。
    entry["subtitle"] = _txt or _other_sub
    entry["subtitle_srt"] = _srt  # 可选增强，记录池内相对路径
    # 公众号图文（2026-11-19）：P0-2 收集正文图片到 images[]；P0-3 覆盖 media_type。
    # _extras 已是「池内相对路径」，直接筛 IMG_EXTS 即可，无需二次扫目录。
    # 封面也在其中，前端首图可直接取 entry["cover"]。
    if source_type == "wechat_article":
        entry["images"] = [e for e in _extras if e.lower().endswith(IMG_EXTS)]
        entry["media_type"] = "article"   # .html 的 media_type_of 为 other，article 场景显式覆盖
        # 发布日期 / 内容子类型（2026-11-23）：随 payload 落 entry，供卡片显示/筛选/排序。
        # 仅文章分支写入，视频等其它资源零影响；空串表示未知，前端按缺失处理。
        entry["published_at"] = published_at
        entry["content_type"] = content_type
    # subtitle_source：显式传入优先；否则有字幕即记为 official，无则空。
    entry["subtitle_source"] = subtitle_source or ("official" if entry["subtitle"] else "")
    # 封面：显式传入优先；否则把池内封面复制进缩略图缓存、以缓存名回填
    # （前端只认 /api/thumbnail-cache/{缓存名}，直接写相对路径会 404 显示「无封面」）
    _cover_in = cover or cover_candidate or ""
    if _cover_in and "/" not in _cover_in and "\\" not in _cover_in and ":" not in _cover_in:
        entry["cover"] = _cover_in          # 已是缓存文件名（上传/老数据），直接用
    elif _cover_in:
        _abs = _cover_in if os.path.isabs(_cover_in) else os.path.join(DOWNLOADS, _cover_in)
        entry["cover"] = _cache_cover_file(_abs) or _cover_in
    else:
        entry["cover"] = ""
    # meta.json 衍生物（O3 解耦）：同主干 .json 入池后记录其相对路径，供前端/下游读取资源元数据
    meta_candidate = next((e for e in _extras if e.lower().endswith(".json")), "")
    entry["meta"] = meta_candidate
    replaced_rel = _add_to_collection(owner, entry, target_cid, target_name)
    # R2（换内容回收，2026-10-21）：登记同 rid 下无引用的旧 body_key8 子目录到回收站（物理保留）。
    # keep_versions=True（ONLYOFFICE 在线编辑）：旧版本属于「文件内部历史」，由 version_log
    # 管理，不作为独立回收站条目——前端只认一个当前版本，删除也是 rid 级整体。
    if not keep_versions:
        _recycle_unreferenced_body_dirs(rid, body_key8)
    return rid, dedup_hit, rel_main, replaced_rel


# ===================== 上传 ⑤ attach 补挂 + pending 兜底（2026-10-22） =====================
# 资源主体-衍生物模型：视频先入池，之后可再传字幕/封面/meta 挂到已存在的资源；
# 若衍生物先到、资源尚不存在，则暂存 _pending_attach/<归一主干>/，等视频入池后自动补挂。

def _match_siblings_by_stem(stem, bucket, consumed):
    """在 bucket（basename->abs_path）中找出与视频主干 stem 同名的字幕/封面/meta。

    配对规则与资源池一致：先剥 [BV号]、再剥 _字幕 标记、最后 normalize_stem（去分P序号前缀），
    相等即视为同源衍生物。命中项记入 consumed，避免被多个视频重复配对。"""
    nb = _norm_stem(stem)
    out = []
    if not nb:
        return out
    for name, path in bucket.items():
        if name in consumed:
            continue
        base = os.path.splitext(name)[0]
        if _norm_stem(base) == nb:
            out.append(path)
            consumed.add(name)
    return out


def _find_resource_by_stem(sid, stem):
    """在本用户所有合集里，按归一主干找到已存在的资源（返回 (rid, body_key8)）。"""
    nb = _norm_stem(stem)
    if not nb:
        return None, None
    cols = _sid_collections(sid)
    for c in cols:
        if c.get("id") == "__trash__":
            continue
        for it in c.get("items", []):
            base = os.path.basename((it.get("rel_path") or "").replace("\\", "/"))
            ibase = os.path.splitext(base)[0]
            if (ibase == stem or _norm_stem(ibase) == nb):
                return it.get("resource_id"), it.get("body_key8")
    return None, None


def _attach_siblings_to_existing(sid, name, subs, covers, metas, target_cid="default"):
    """把（已无视频同批的）字幕/封面/meta 挂到「已存在的同名资源」。

    定位锚点：归一主干 stem（资源未传 rid 时由文件名推导）。命中后把文件迁入资源池目录，
    并就地更新该 resource_id 在「本用户所有合集」里的条目（跨合集同步）。
    返回是否成功挂上（False 表示未找到可挂资源，调用方应转 pending 兜底）。"""
    if not (subs or covers or metas):
        return False
    rid, body_key8 = _find_resource_by_stem(sid, os.path.splitext(name)[0])
    if not rid or not body_key8:
        return False
    _attach_files_into_pool(sid, rid, body_key8, subs, covers, metas)
    return True


def _prune_pool_files(pool_dir, exts, keep_rels=None):
    """删除池根目录下指定扩展名的文件（keep_rels 除外）——更换封面 / 删除衍生物时清理孤儿。

    池目录与资源一一对应：池根一级的图片即该资源的封面、字幕类文本即其字幕。
    重复上传封面时旧文件若不清理会堆积成孤儿（covers[0] 取新不取旧，旧文件永无引用）。
    仅删池根一级的普通文件，不碰子目录（如 users/<hash>/ 文章目录）。
    """
    if not pool_dir or not os.path.isdir(pool_dir):
        return 0
    keep = set()
    for r in (keep_rels or []):
        keep.add(os.path.basename((r or "").replace("\\", "/")))
    removed = 0
    try:
        for fn in os.listdir(pool_dir):
            fp = os.path.join(pool_dir, fn)
            if not os.path.isfile(fp) or fn in keep:
                continue
            if os.path.splitext(fn)[1].lower() in exts:
                try:
                    os.remove(fp)
                    removed += 1
                except Exception:
                    pass
    except Exception:
        pass
    return removed


def _attach_files_into_pool(sid, rid, body_key8, subs, covers, metas):
    """把已配对的字幕/封面/meta 迁入资源池目录，并同步更新本用户所有合集中引用该 resource_id 的条目。"""
    pool_dir = _pool_dir(rid, body_key8)
    if not os.path.isdir(pool_dir):
        return
    moved = []
    for p in (list(subs) + list(covers) + list(metas)):
        if not p or not os.path.isfile(p):
            continue
        dst = _uniq_path(os.path.join(pool_dir, os.path.basename(p)))
        try:
            shutil.move(p, dst)
            moved.append(os.path.relpath(dst, DOWNLOADS))
        except Exception:
            pass
    if not moved:
        return
    rel_subs  = [m for m in moved if m.lower().endswith(SUB_EXTS)]
    rel_covs  = [m for m in moved if m.lower().endswith(IMG_EXTS)]
    rel_metas = [m for m in moved if m.lower().endswith(META_EXT)]
    if rel_covs:
        # 更换封面语义：新封面上传即替换，清掉池根旧封面避免孤儿堆积
        _prune_pool_files(pool_dir, IMG_EXTS, keep_rels=rel_covs)
    _update_resource_fields(sid, rid, rel_subs, rel_covs, rel_metas)


def _update_resource_fields(sid, rid, subs, covers, metas):
    """把新挂的字幕/封面/meta 回填到本用户所有合集中引用 resource_id==rid 的条目（跨合集同步）。"""
    cols = _sid_collections(sid)
    changed = False
    for c in cols:
        if c.get("id") == "__trash__":
            continue
        for it in c.get("items", []):
            if it.get("resource_id") != rid:
                continue
            if subs:
                _txt = next((s for s in subs if s.lower().endswith(".txt")), "")
                _srt = next((s for s in subs if s.lower().endswith(".srt")), "")
                if _txt:
                    it["subtitle"] = _txt
                if _srt:
                    it["subtitle_srt"] = _srt
                if not it.get("subtitle_source"):
                    it["subtitle_source"] = "official" if it.get("subtitle") else ""
                changed = True
            if covers:
                cov = covers[0]
                abs_cov = cov if os.path.isabs(cov) else os.path.join(DOWNLOADS, cov)
                it["cover"] = _cache_cover_file(abs_cov) or cov
                changed = True
            if metas:
                it["meta"] = metas[0]
                changed = True
    if changed:
        _save_collections()


def _pending_attach_dir(sid):
    return os.path.join(user_root(sid), "_pending_attach")


def _stage_pending_attach(sid, name, path):
    """视频尚未入池时，先把字幕/封面/meta 按归一主干存进 pending，待视频入池后补挂。"""
    nb = _norm_stem(os.path.splitext(name)[0]) or "_unknown"
    d = os.path.join(_pending_attach_dir(sid), nb)
    os.makedirs(d, exist_ok=True)
    try:
        shutil.move(path, _uniq_path(os.path.join(d, os.path.basename(path))))
    except Exception:
        pass


def _flush_pending_attach(sid, rid, body_key8, stem):
    """视频入池后，把 pending 里同主干的字幕/封面/meta 补挂进该资源池目录。"""
    nb = _norm_stem(stem)
    if not nb:
        return
    target = os.path.join(_pending_attach_dir(sid), nb)
    if not os.path.isdir(target):
        return
    subs, covers, metas = [], [], []
    for fn in os.listdir(target):
        fp = os.path.join(target, fn)
        if not os.path.isfile(fp):
            continue
        ext = os.path.splitext(fn)[1].lower()
        if ext in SUB_EXTS:
            subs.append(fp)
        elif ext in IMG_EXTS:
            covers.append(fp)
        elif ext in META_EXT:
            metas.append(fp)
    if subs or covers or metas:
        _attach_files_into_pool(sid, rid, body_key8, subs, covers, metas)
    try:
        os.rmdir(target)
    except OSError:
        pass


# ===================== A：定向补录（按 rid 直接绑定，2026-10-23） =====================
# 上传时的自动配对靠「文件名主干相同」，用户在补封面/字幕时很容易配不上而落入 pending。
# 本接口绕开文件名匹配，直接把衍生物绑定到用户显式指定的 resource_id。

def _body_key8_for_rid(sid, rid):
    """在本用户所有合集（不含回收站）里按 resource_id 反查 body_key8。"""
    if not rid:
        return None
    for c in _sid_collections(sid):
        if c.get("id") == "__trash__":
            continue
        for it in c.get("items", []):
            if (it.get("resource_id") or "") == rid and it.get("body_key8"):
                return it.get("body_key8")
    return None


class PendingResolveReq(BaseModel):
    stem: str
    rid: str = ""


@app.post("/api/resource/{rid}/attach")
async def attach_to_resource(
    rid: str,
    files: list[UploadFile] = File(...),
    sid: str = Depends(current_identity),
):
    """定向补录：把字幕 / 封面 / meta 直接挂到指定资源（不依赖文件名匹配）。

    只接收衍生物；视频/音频与其他类型一律忽略（补录不新建资源）。
    """
    body_key8 = _body_key8_for_rid(sid, rid)
    if not body_key8:
        raise HTTPException(status_code=404, detail="资源不存在或无权操作")
    if not os.path.isdir(_pool_dir(rid, body_key8)):
        raise HTTPException(status_code=404, detail="资源池目录不存在（可能已被清理）")
    stage_dir = os.path.join(user_root(sid), "_staging")
    os.makedirs(stage_dir, exist_ok=True)
    subs, covers, metas, skipped = [], [], [], []
    for f in files:
        ext = os.path.splitext(f.filename or "")[1].lower()
        if ext not in SUB_EXTS and ext not in IMG_EXTS and ext not in META_EXT:
            skipped.append(f.filename or "")
            continue
        try:
            data = await f.read()
        except Exception:
            skipped.append(f.filename or "")
            continue
        safe = _safe_upload_name(f.filename)
        dest = _uniq_path(os.path.join(stage_dir, safe))
        with open(dest, "wb") as w:
            w.write(data)
        if ext in SUB_EXTS:
            subs.append(dest)
        elif ext in IMG_EXTS:
            covers.append(dest)
        else:
            metas.append(dest)
    attached = len(subs) + len(covers) + len(metas)
    if attached:
        _attach_files_into_pool(sid, rid, body_key8, subs, covers, metas)
    return {"ok": True, "attached": attached, "skipped": skipped,
            "rid": rid}


class DetachReq(BaseModel):
    kind: str = "subtitle"  # subtitle=删除字幕（txt/srt 及池内字幕类文件）；cover=删除封面


@app.post("/api/resource/{rid}/detach")
def detach_from_resource(rid: str, req: DetachReq, sid: str = Depends(current_identity)):
    """删除资源的字幕或封面：清空合集中的字段引用 + 清理池根对应文件（不可恢复）。

    与补录（attach）互补：补录管「挂上」，本接口管「摘下」。
    删除字幕会同时清掉 subtitle/subtitle_srt/subtitle_source 三个字段；
    删除封面清掉 cover 字段。池内文件一并物理删除，避免孤儿。
    """
    kind = (req.kind or "").strip().lower()
    if kind not in ("subtitle", "cover"):
        raise HTTPException(status_code=400, detail="kind 仅支持 subtitle / cover")
    body_key8 = _body_key8_for_rid(sid, rid)
    if not body_key8:
        raise HTTPException(status_code=404, detail="资源不存在或无权操作")
    pool_dir = _pool_dir(rid, body_key8)
    exts = SUB_EXTS if kind == "subtitle" else IMG_EXTS
    removed = _prune_pool_files(pool_dir, exts)
    cols = _sid_collections(sid)
    cleared = 0
    for c in cols:
        if c.get("id") == "__trash__":
            continue
        for it in c.get("items", []):
            if it.get("resource_id") != rid:
                continue
            if kind == "subtitle":
                if not (it.get("subtitle") or it.get("subtitle_srt")):
                    continue
                it["subtitle"] = ""
                it["subtitle_srt"] = ""
                it["subtitle_source"] = ""
            else:
                if not it.get("cover"):
                    continue
                it["cover"] = ""
            cleared += 1
    if cleared:
        _save_collections()
    return {"ok": True, "kind": kind, "removed": removed, "cleared": cleared,
            "rid": rid}


# ===================== B：pending 可视化（列表 / 手动挂载 / 丢弃，2026-10-23） =====================
# 历史遗留的 _pending_attach 目录对用户完全不可见，这里把它暴露出来并允许人工处置。

@app.get("/api/pending-attach")
def pending_attach_list(sid: str = Depends(current_identity)):
    """列出 _pending_attach 下所有暂存主干及其文件。"""
    root = _pending_attach_dir(sid)
    out = []
    if os.path.isdir(root):
        for stem in sorted(os.listdir(root)):
            d = os.path.join(root, stem)
            if not os.path.isdir(d):
                continue
            files = []
            for fn in sorted(os.listdir(d)):
                fp = os.path.join(d, fn)
                if os.path.isfile(fp):
                    files.append({"name": fn, "size": os.path.getsize(fp)})
            if files:
                out.append({"stem": stem, "files": files, "count": len(files)})
    return {"ok": True, "items": out}


@app.post("/api/pending-attach/resolve")
def pending_attach_resolve(req: PendingResolveReq, sid: str = Depends(current_identity)):
    """把某个待补挂主干下的文件，手动挂到指定资源。"""
    d = os.path.join(_pending_attach_dir(sid), os.path.basename(req.stem))
    if not os.path.isdir(d):
        raise HTTPException(status_code=404, detail="待补挂目录不存在")
    body_key8 = _body_key8_for_rid(sid, req.rid)
    if not body_key8:
        raise HTTPException(status_code=404, detail="目标资源不存在或无权操作")
    subs, covers, metas = [], [], []
    for fn in os.listdir(d):
        fp = os.path.join(d, fn)
        if not os.path.isfile(fp):
            continue
        ext = os.path.splitext(fn)[1].lower()
        if ext in SUB_EXTS:
            subs.append(fp)
        elif ext in IMG_EXTS:
            covers.append(fp)
        elif ext in META_EXT:
            metas.append(fp)
    n = len(subs) + len(covers) + len(metas)
    if n:
        _attach_files_into_pool(sid, req.rid, body_key8, subs, covers, metas)
    shutil.rmtree(d, ignore_errors=True)
    return {"ok": True, "attached": n, "rid": req.rid}


@app.post("/api/pending-attach/delete")
def pending_attach_delete(req: PendingResolveReq, sid: str = Depends(current_identity)):
    """丢弃某个待补挂主干（物理删除暂存目录）。"""
    d = os.path.join(_pending_attach_dir(sid), os.path.basename(req.stem))
    if not os.path.isdir(d):
        raise HTTPException(status_code=404, detail="待补挂目录不存在")
    shutil.rmtree(d, ignore_errors=True)
    return {"ok": True, "deleted": req.stem}


class IngestReq(BaseModel):
    user: str = ""
    rid: str
    body_key8: str = ""  # 兼容旧生产者；RM 现按内容哈希重算（见 /api/ingest，O3 治本）
    staged_path: str
    title: str = ""
    subtitle_path: str = ""       # 主字幕（建议 _字幕.txt，RM match_subtitle 契约）
    subtitle_srt_path: str = ""   # R1（2026-10-21）：增强字幕 srt，入池后记录到 subtitle_srt
    cover: str = ""
    extras: list[str] = []        # R1（2026-10-21）：任意额外文件（srt/其它字幕/封面等），向后兼容
    target_cid: str = "default"
    source_type: str = "video"    # 资源大类（中性默认）；公众号图文生产者传 "wechat_article"
    url: str = ""                 # 文章永久直链（公众号归档场景）
    published_at: str = ""        # 公众号发布日期 YYYY-MM-DD（2026-11-23；默认空串，老生产者不受影响）
    content_type: str = ""        # 内容子类型 图文/贴图（2026-11-23；空串=未知，不猜映射）


@app.post("/api/ingest")
def ingest(req: IngestReq, sid: str = Depends(current_identity)):
    """生产者统一入口：把已 staging 到本地的文件迁入资源池并登记引用。

    入参（见 RM-实施指引 §2.1）：user / rid / staged_path / title / subtitle_path? / cover?。
    rid 由生产者（如下载器 / agent）按规范派生后传入（资源级稳定主键，RM 尊重之）。
    body_key8 不再由生产者决定：RM 按「文件内容哈希」派生（O3 治本，2026-10-20），
    保证无论生产者如何命名，同内容必落同一子目录、入池即去重。传入的 body_key8 被忽略。"""
    owner = req.user or sid
    if not req.rid or not req.staged_path:
        raise HTTPException(400, "rid / staged_path 均为必填")
    if not os.path.isfile(req.staged_path):
        raise HTTPException(400, f"staged_path 不存在: {req.staged_path}")
    # body_key8 由 RM 按内容哈希派生（覆盖生产者传入值），统一资源池去重语义
    _h = _sha256_of_file(req.staged_path)
    body_key8 = _body_key8_from_hash(_h)
    extras = [p for p in (req.subtitle_path, req.subtitle_srt_path, req.cover) + tuple(req.extras)
               if p and os.path.isfile(p)]
    rid, dedup_hit, rel, replaced = _ingest_into_pool(
        owner, req.rid, body_key8, req.staged_path, extras, req.title, req.target_cid,
        content_sha256=_h, source_type=req.source_type, url=req.url,
        published_at=req.published_at, content_type=req.content_type,
    )
    # R3（2026-10-21）：返回被替换掉的旧版本 rel_path（换内容场景），无替换则为空串。
    return {"ok": True, "rid": rid, "resource_id": rid, "dedup_hit": dedup_hit,
            "rel_path": rel, "replaced_rel_path": replaced or ""}


class ImportDirReq(BaseModel):
    dir_path: str
    user: str = ""
    target_cid: str = "default"


@app.post("/api/import-dir")
def import_dir(req: ImportDirReq, sid: str = Depends(current_identity)):
    """目录导入：遍历目录，按内容哈希派生 rid、按内容派生（内容哈希 [16:24]）body_key8，
    复制（源目录原封不动）入资源池并登记引用。见 RM-实施指引 §2.3。
    body_key8 与文件名/大小无关，配合 _ingest_into_pool 的内容级去重保证同内容只存一份。

    定位：本接口是「保留源的一次性运维/迁移工具」，用于从备份或外部目录批量迁入，
    与 inbox watcher 的「移动·处理即清」自动通道分工不同。
    ⚠️ 请勿对本服务的 inbox 目录（watcher 工作区）调用本接口——inbox 由 watcher 独占，
    误用会扫到 .processing/.failed 半组或失败隔离文件，破坏自动导入的清洁性。"""
    owner = req.user or sid
    dp = req.dir_path
    if not os.path.isdir(dp):
        raise HTTPException(400, f"目录不存在: {dp}")
    media_files, side_files = [], []
    for root, dirs, fnames in os.walk(dp):
        # 护栏：跳过 watcher 工作区，避免与 inbox watcher 冲突、读到半组或已隔离文件
        dirs[:] = [d for d in dirs if d not in (".processing", ".failed")]
        for fn in fnames:
            ext = os.path.splitext(fn)[1].lower()
            fp = os.path.join(root, fn)
            if ext in MAIN_EXT:
                media_files.append(fp)
            elif ext in SIDE_EXT and not fn.endswith(".meta.json"):
                # 排除 inbox watcher 的组锚文件，避免被当 sidecar 误传/污染资源池
                side_files.append(fp)
    side_map = {os.path.basename(p): p for p in side_files}
    stage_dir = os.path.join(user_root(owner), "_staging")
    os.makedirs(stage_dir, exist_ok=True)
    added = 0
    skipped = 0
    for mp in media_files:
        try:
            h = _sha256_of_file(mp)
            rid = "r" + h[:15]
        except OSError:
            skipped += 1
            continue
        body_key8 = _body_key8_from_hash(h)
        content_sha256 = h
        # 复制语义：源目录不动，副本进 staging 再迁入池
        dest = _uniq_path(os.path.join(stage_dir, os.path.basename(mp)))
        try:
            shutil.copy2(mp, dest)
        except OSError:
            skipped += 1
            continue
        stem = os.path.splitext(os.path.basename(mp))[0]
        IMG_EXTS = (".jpg", ".jpeg", ".png", ".webp")
        extras = []
        # 复制语义：侧车（字幕 + 同名封面）也先拷进 staging，避免把源目录的侧车 move 走
        sub_fn = match_subtitle(stem, set(side_map.keys())) if side_map else ""
        if sub_fn:
            sub_src = side_map[sub_fn]
            sub_dest = _uniq_path(os.path.join(stage_dir, os.path.basename(sub_src)))
            try:
                shutil.copy2(sub_src, sub_dest)
                extras.append(sub_dest)
            except OSError:
                pass
        # 同名封面（与视频同 stem，扩展名在 IMG_EXTS）——与 watcher 的 B2 封面入库保持一致
        cover_fn = next((fn for fn in side_map
                         if fn in {stem + e for e in IMG_EXTS}), None)
        if cover_fn:
            cover_src = side_map[cover_fn]
            cover_dest = _uniq_path(os.path.join(stage_dir, os.path.basename(cover_src)))
            try:
                shutil.copy2(cover_src, cover_dest)
                extras.append(cover_dest)
            except OSError:
                pass
        try:
            _src_type = "office" if mp.lower().endswith(OFFICE_EXT) else "video"
            _ingest_into_pool(owner, rid, body_key8, dest, extras,
                              _title_from_filename(mp), target_cid=req.target_cid,
                              content_sha256=content_sha256, source_type=_src_type)
            added += 1
        except HTTPException:
            skipped += 1
    return {"ok": True, "added": added, "skipped": skipped, "total": len(media_files)}


if __name__ == "__main__":
    import uvicorn
    # 直接 python app.py 启动时也拉起 inbox watcher（run_server.py 已含，import 本模块时不重复执行）
    import inbox_watcher
    inbox_watcher.start_inbox_watcher()
    uvicorn.run(app, host=cfg["host"], port=cfg["port"], log_level="info")
