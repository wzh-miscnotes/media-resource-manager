# -*- coding: utf-8 -*-
"""RM inbox watcher（方案 A 闭环最后一环）。

常驻线程：轮询 RM_INBOX_DIR，以 ``{stem}.meta.json`` 为组锚识别「视频 + 字幕 + 封面 + meta」
四件套，复用 ``app._ingest_into_pool`` 入池，处理即清（防堆积 / 防重复引用）。

纯内部机制，不新增任何对外 API。触发与容错：
  * 半组保护：整组先 move 到 ``inbox/.processing/{stem}/`` 再入池，中途重启不会读到半组；
  * 失败重试：异常 → 组留 ``.processing``，下轮重试；超 ``RM_INBOX_MAX_RETRY`` 移 ``.failed/``；
  * 单组失败不阻塞：try/except 隔离，后续组照常处理。
"""
import os
import time
import json
import shutil
import threading
import hashlib

from config import cfg
from app import (
    _ingest_into_pool,
    _sha256_of_file,
    _body_key8_from_hash,
    match_subtitle,
    _title_from_filename,
    MEDIA_EXT,
)

IMG_EXTS = (".jpg", ".jpeg", ".png", ".webp")
SUB_EXTS = (".srt", ".vtt", ".ass", ".xml", ".txt")
# 无 meta 的孤立媒体：跳过最近 N 秒内改动者，避免吞掉下载端尚未写完的半截文件。
ORPHAN_MIN_AGE_SEC = 15


def _log(msg):
    print(f"[inbox-watch] {msg}", flush=True)


def _load_meta(meta_path):
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _retry_count(proc_dir):
    try:
        with open(os.path.join(proc_dir, ".retry"), "r", encoding="utf-8") as f:
            return int((f.read() or "0").strip() or "0")
    except Exception:
        return 0


def _set_retry(proc_dir, n):
    try:
        with open(os.path.join(proc_dir, ".retry"), "w", encoding="utf-8") as f:
            f.write(str(n))
    except Exception:
        pass


def _ingest_group(proc_dir, stem, owner_default):
    """对 ``.processing/{stem}/`` 内的一组文件执行入池。成功返回 (rid, dedup, owner)；
    失败抛异常（由调用方做重试 / .failed 处理）。"""
    files = [f for f in os.listdir(proc_dir) if os.path.isfile(os.path.join(proc_dir, f))]
    name_set = set(files)
    meta = _load_meta(os.path.join(proc_dir, stem + ".meta.json"))
    owner = (meta.get("owner") or "").strip() or owner_default
    title = meta.get("title") or ""
    vid = meta.get("vid") or ""
    seq = meta.get("seq") or ""
    target_cid = meta.get("target_cid") or "default"

    # 视频（必需）
    vids = [f for f in files if f.lower().endswith(MEDIA_EXT)]
    if not vids:
        raise RuntimeError("group has no media file")
    vid = max(vids, key=lambda f: os.path.getsize(os.path.join(proc_dir, f)))
    vid_abs = os.path.join(proc_dir, vid)

    # 字幕：主字幕走 match_subtitle（仅认 _字幕.txt，保持契约）；
    # 同时收集同 stem 的其它字幕（srt/vtt/ass/xml 等）一并作为 extras 入池。
    # 背景（2026-10-21）：下载端是 txt+srt 双写，但此前只传 match_subtitle 的单个结果，
    # srt 未进 extras → 入池后 .processing 清理时被物理删除，池内只剩 txt。
    sub_fn = match_subtitle(stem, name_set)
    sub_files = [sub_fn] if sub_fn else []
    for f in sorted(files):
        if f in sub_files:
            continue
        fbase, fext = os.path.splitext(f)
        if fext.lower() in SUB_EXTS and (fbase == stem or fbase == stem + "_字幕"):
            sub_files.append(f)
    sub_abs_list = [os.path.join(proc_dir, f) for f in sub_files
                    if os.path.isfile(os.path.join(proc_dir, f))]
    # 封面：同 stem 的图
    cover_fn = next((f for f in files
                     if f.lower().endswith(IMG_EXTS) and os.path.splitext(f)[0] == stem), "")
    cover_abs = os.path.join(proc_dir, cover_fn) if cover_fn else ""

    vid_hash = _sha256_of_file(vid_abs)
    rid = "r" + vid_hash[:15]
    body_key8 = _body_key8_from_hash(vid_hash)

    # extras 传绝对路径：_move_staged_to_pool 对绝对路径直接采用，无需依赖 DOWNLOADS 拼接
    extras = [p for p in (sub_abs_list + [cover_abs]) if p and os.path.isfile(p)]
    title_final = title or _title_from_filename(vid)

    # R1/R2/R3（2026-10-21）：_ingest_into_pool 返回 4 元组（多 replaced_rel_path），
    # 此处必须解包 4 个，否则 ValueError: too many values to unpack（曾致 watcher 全量失败）。
    rid_out, dedup, _rel, _replaced = _ingest_into_pool(
        owner, rid, body_key8, vid_abs, extras, title_final,
        target_cid=target_cid, vid=vid, seq=seq, content_sha256=vid_hash,
    )
    return rid_out, dedup, owner


def _stage_group(inbox, stem):
    """把 inbox 根目录中属于该 stem 的四件套 move 到 ``inbox/.processing/{stem}/``。
    返回 proc_dir；无视频或空组则回退并返回 None。"""
    proc_dir = os.path.join(inbox, ".processing", stem)
    if os.path.exists(proc_dir):
        return proc_dir  # 已在处理中（理论上不会，resume 已接管）
    os.makedirs(proc_dir, exist_ok=True)
    moved = []
    try:
        for fn in sorted(os.listdir(inbox)):
            fp = os.path.join(inbox, fn)
            if not os.path.isfile(fp):
                continue
            base, ext = os.path.splitext(fn)
            # 组归属：视频/封面 = 精确 stem；字幕 = {stem}_字幕.{txt,srt,...}；外加 {stem}.meta.json。
            # 注意字幕文件名主干是 stem + "_字幕"，不能只判 base == stem。
            is_group = (
                fn == stem + ".meta.json"
                or (ext.lower() in (MEDIA_EXT + IMG_EXTS + SUB_EXTS)
                    and (base == stem or base == stem + "_字幕"))
            )
            if is_group:
                shutil.move(fp, os.path.join(proc_dir, fn))
                moved.append(fn)
        if not moved or not any(m.lower().endswith(MEDIA_EXT) for m in moved):
            # 空组 / 无视频 → 回退，留在 inbox 等下载端补齐
            for m in moved:
                shutil.move(os.path.join(proc_dir, m), os.path.join(inbox, m))
            shutil.rmtree(proc_dir, ignore_errors=True)
            return None
        return proc_dir
    except Exception as e:
        for m in moved:
            try:
                shutil.move(os.path.join(proc_dir, m), os.path.join(inbox, m))
            except Exception:
                pass
        shutil.rmtree(proc_dir, ignore_errors=True)
        raise RuntimeError(f"stage failed: {e}")


def _run_ingest(inbox, proc_dir, stem, owner_default, max_retry, is_orphan):
    try:
        rid, dedup, owner = _ingest_group(proc_dir, stem, owner_default)
        _log(f"owner={owner} stem={stem} rid={rid} dedup={dedup}"
             + (" ORPHAN_NO_META" if is_orphan else ""))
        shutil.rmtree(proc_dir, ignore_errors=True)  # 处理即清
    except Exception as e:
        n = _retry_count(proc_dir) + 1
        _set_retry(proc_dir, n)
        if n > max_retry:
            failed = os.path.join(inbox, ".failed", stem)
            shutil.rmtree(failed, ignore_errors=True)
            try:
                shutil.move(proc_dir, failed)
            except Exception:
                pass
            _log(f"ERROR stem={stem} moved_to_.failed after {n} retries: {e}")
        else:
            _log(f"WARN stem={stem} ingest failed (retry {n}/{max_retry}): {e}")


def _process_group(inbox, meta_path, owner_default, max_retry):
    stem = os.path.basename(meta_path)[:-len(".meta.json")]
    # 预检：视频必须已在 inbox 根目录（meta 是下载端最后落盘的锚，代表整组就绪）
    vid_ready = any(
        fn.lower().endswith(MEDIA_EXT) and os.path.splitext(fn)[0] == stem
        for fn in os.listdir(inbox)
    )
    if not vid_ready:
        return  # 半组：留在 inbox，等下一轮再判
    proc_dir = _stage_group(inbox, stem)
    if not proc_dir:
        return
    _run_ingest(inbox, proc_dir, stem, owner_default, max_retry, is_orphan=False)


def _process_orphan(inbox, vid_file, owner_default, max_retry):
    """无 meta 的孤立媒体：宽容导入（默认 owner + 降级日志）。"""
    stem = os.path.splitext(vid_file)[0]
    proc_dir = os.path.join(inbox, ".processing", stem)
    if os.path.exists(proc_dir):
        return
    os.makedirs(proc_dir, exist_ok=True)
    try:
        shutil.move(os.path.join(inbox, vid_file), os.path.join(proc_dir, vid_file))
        for fn in sorted(os.listdir(inbox)):  # 顺带搬同 stem 的字幕/封面
            fp = os.path.join(inbox, fn)
            if not os.path.isfile(fp):
                continue
            b, ext = os.path.splitext(fn)
            if ext.lower() in (IMG_EXTS + SUB_EXTS) and (b == stem or b == stem + "_字幕"):
                shutil.move(fp, os.path.join(proc_dir, fn))
    except Exception:
        shutil.rmtree(proc_dir, ignore_errors=True)
        return
    _run_ingest(inbox, proc_dir, stem, owner_default, max_retry, is_orphan=True)


def _resume_processing(inbox, owner_default, max_retry):
    """处理 .processing/ 残留组：覆盖「导入中途崩溃重启」与「失败未达上限」两种续跑场景。"""
    proc_root = os.path.join(inbox, ".processing")
    if not os.path.isdir(proc_root):
        return
    for stem in sorted(os.listdir(proc_root)):
        proc_dir = os.path.join(proc_root, stem)
        if not os.path.isdir(proc_dir):
            continue
        _run_ingest(inbox, proc_dir, stem, owner_default, max_retry, is_orphan=False)


def _inbox_watch_loop(inbox, poll, owner_default, max_retry):
    _log(f"loop start: dir={inbox} poll={poll}s owner={owner_default} max_retry={max_retry}")
    while True:
        try:
            if not os.path.isdir(inbox):
                time.sleep(poll)
                continue
            # 0) 续跑 .processing 残留（崩溃恢复 / 失败重试）
            _resume_processing(inbox, owner_default, max_retry)

            # 1) meta 锚定的完整组
            for fn in sorted(os.listdir(inbox)):
                if fn.endswith(".meta.json") and os.path.isfile(os.path.join(inbox, fn)):
                    try:
                        _process_group(inbox, os.path.join(inbox, fn), owner_default, max_retry)
                    except Exception as e:
                        _log(f"ERROR process_group {fn}: {e}")

            # 2) 无 meta 孤立媒体（宽容 + 年龄护栏）
            now = time.time()
            meta_stems = {os.path.basename(f)[:-len(".meta.json")]
                         for f in os.listdir(inbox) if f.endswith(".meta.json")}
            for fn in sorted(os.listdir(inbox)):
                fp = os.path.join(inbox, fn)
                if not os.path.isfile(fp) or not fn.lower().endswith(MEDIA_EXT):
                    continue
                stem = os.path.splitext(fn)[0]
                if stem in meta_stems:
                    continue  # 属 meta 组，交给上面
                if now - os.path.getmtime(fp) < ORPHAN_MIN_AGE_SEC:
                    continue  # 可能还在写，下一轮再判
                try:
                    _process_orphan(inbox, fn, owner_default, max_retry)
                except Exception as e:
                    _log(f"ERROR process_orphan {fn}: {e}")
        except Exception as e:
            _log(f"loop error: {e}")
        time.sleep(poll)


def start_inbox_watcher():
    inbox = cfg.get("RM_INBOX_DIR", "")
    if not inbox:
        _log("disabled (RM_INBOX_DIR empty)")
        return
    try:
        poll = int(cfg.get("RM_INBOX_POLL_SEC", 10) or 10)
        max_retry = int(cfg.get("RM_INBOX_MAX_RETRY", 5) or 5)
    except (TypeError, ValueError):
        poll, max_retry = 10, 5
    owner_default = (cfg.get("RM_INBOX_DEFAULT_OWNER") or "admin@local") or "admin@local"
    # 预创建 .processing / .failed，避免首次 move 抖动
    os.makedirs(os.path.join(inbox, ".processing"), exist_ok=True)
    os.makedirs(os.path.join(inbox, ".failed"), exist_ok=True)
    t = threading.Thread(
        target=_inbox_watch_loop, args=(inbox, poll, owner_default, max_retry),
        name="inbox-watcher", daemon=True,
    )
    t.start()
    _log(f"started (thread={t.name})")
