#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""资源池 body_key8 迁移脚本（O3 治本，2026-10-20）。

背景
----
历史上 RM 的 body_key8 = sha256(文件名|大小)[:8]，与文件内容无关，导致
「同内容不同文件名」被存成两份。现已把派生公式改为「文件内容哈希的 [16:24] 窗口」
（见 app.py::_body_key8_from_hash，与 rid 的 [:15] 同源、不重叠）。

本脚本把 **存量** 资源池目录重排到新公式：
  - 扫描 resources/<rid>/<old_bk8>/ 下每个子目录，用其中媒体文件的内容哈希算出
    规范 new_bk8 = sha256(content).hexdigest()[16:24]；
  - 同一 <rid> 下、内容相同的多个 old_bk8 子目录 → 合并到同一个 new_bk8 子目录
    （内容相同则去重，不同内容如不同画质保留为各自 new_bk8）；
  - 改写 _collections/collections.json 中所有条目的 rel_path / body_key8 / subtitle / cover。

设计要点（安全）
----------------
  - 默认 dry-run：只打印计划，**不改动任何文件**；加 --apply 才真正执行。
  - 改动前自动备份 collections.json（时间戳 .bak）。
  - 与 app.py 公式严格一致（同一哈希窗口），迁移后新导入自动与新目录对齐。
  - 幂等：中途中断可重跑；已迁移子目录 new_bk8 == 计算值，不会再动。
  - rid 不动（内容哈希 rid 或 vid|seq rid 都保持），仅重排 body_key8 子目录；
    因此对「内容哈希 rid」和「vid|seq rid（下载器投递）」都安全。

⚠️ 运行前请停止 rm_app（避免并发写 collections.json），并在备份卷上先 dry-run 复核。

用法
----
  python migrate_body_key8.py --downloads-dir /home/fastgpt/media_data           # 仅预览
  python migrate_body_key8.py --downloads-dir /home/fastgpt/media_data --apply   # 执行
"""

import argparse
import hashlib
import json
import os
import shutil
import sys
import time

# 与 app.py 完全一致：内容哈希的 [16:24] 窗口
_BODY_KEY8_WIN = slice(16, 24)
# 与 app.py::MEDIA_EXT 对齐
MEDIA_EXT = (".mp4", ".mkv", ".webm", ".flv", ".mov", ".m4a", ".mp3", ".aac")


def sha256_of_file(fp):
    h = hashlib.sha256()
    with open(fp, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def body_key8_from_hash(h):
    return h[_BODY_KEY8_WIN]


def _is_media(fn):
    return fn.lower().endswith(MEDIA_EXT)


def discover(downloads_dir):
    """扫描 resources/<rid>/<bk8>/ 子目录，规划重排。

    返回:
      subdirs: list of dict{rid, old_bk8, new_bk8, media_hash, files:[abs,...], has_media:bool}
      subdir_map: {(rid, old_bk8): new_bk8}
    """
    resources_dir = os.path.join(downloads_dir, "resources")
    subdirs = []
    if not os.path.isdir(resources_dir):
        return subdirs, {}
    for rid in sorted(os.listdir(resources_dir)):
        rid_dir = os.path.join(resources_dir, rid)
        if not os.path.isdir(rid_dir):
            continue
        for bk8 in sorted(os.listdir(rid_dir)):
            sub = os.path.join(rid_dir, bk8)
            if not os.path.isdir(sub):
                continue
            files = [os.path.join(sub, f) for f in os.listdir(sub)
                     if os.path.isfile(os.path.join(sub, f))]
            media = [f for f in files if _is_media(os.path.basename(f))]
            rec = {
                "rid": rid, "old_bk8": bk8, "new_bk8": None,
                "media_hash": None, "files": files, "has_media": bool(media),
            }
            if media:
                # 取第一个媒体文件的内容哈希作为该子目录内容指纹
                rec["media_hash"] = sha256_of_file(media[0])
                rec["new_bk8"] = body_key8_from_hash(rec["media_hash"])
            subdirs.append(rec)

    subdir_map = {}
    for rec in subdirs:
        if rec["has_media"]:
            subdir_map[(rec["rid"], rec["old_bk8"])] = rec["new_bk8"]
    return subdirs, subdir_map


def plan_moves(subdirs):
    """为每个待迁移子目录规划文件移动；合并时按内容去重，碰撞则用后缀保留。"""
    moves = []  # (src, dst, dedup:bool)
    for rec in subdirs:
        if not rec["has_media"]:
            continue
        _rid, old, new = rec["rid"], rec["old_bk8"], rec["new_bk8"]
        if old == new:
            continue  # 已是规范名，无需动
        # rec["files"][0] 位于 resources/<rid>/<old>/ 下 → 其父的父即 resources/<rid>/
        rid_dir = os.path.dirname(os.path.dirname(rec["files"][0]))
        dst_dir = os.path.join(rid_dir, new)  # resources/<rid>/<new>/
        for src in rec["files"]:
            base = os.path.basename(src)
            dst = os.path.join(dst_dir, base)
            if os.path.abspath(src) == os.path.abspath(dst):
                continue
            dedup = False
            if os.path.exists(dst):
                # 目标已存在：内容相同则去重（删除源），否则保留两份（加后缀）
                try:
                    if sha256_of_file(src) == sha256_of_file(dst):
                        dedup = True
                    else:
                        root, ext = os.path.splitext(dst)
                        i = 1
                        while os.path.exists(f"{root}__dup{i}{ext}"):
                            i += 1
                        dst = f"{root}__dup{i}{ext}"
                except OSError:
                    pass
            moves.append((src, dst, dedup))
    return moves


def remap_rel(rel, subdir_map):
    if not rel:
        return rel
    parts = rel.replace("\\", "/").split("/")
    if len(parts) >= 3 and parts[0] == "resources":
        rid, bk8 = parts[1], parts[2]
        new = subdir_map.get((rid, bk8))
        if new and new != bk8:
            parts[2] = new
            return "/".join(parts)
    return rel


def remap_collections(collections_file, subdir_map):
    """返回 (修改后的 data, 受影响的条目数)。不写盘。"""
    try:
        with open(collections_file, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None, 0
    touched = 0
    for sid, blob in data.items():
        cols = (blob or {}).get("collections")
        if not isinstance(cols, list):
            continue
        for col in cols:
            for it in (col.get("items") or []):
                changed = False
                # 主条目：由 rel_path 解析 (rid, old_bk8)，命中映射则改写 rel_path + body_key8
                rp = it.get("rel_path")
                if isinstance(rp, str) and rp.startswith("resources/"):
                    parts = rp.replace("\\", "/").split("/")
                    if len(parts) >= 3:
                        rid, old_bk8 = parts[1], parts[2]
                        new = subdir_map.get((rid, old_bk8))
                        if new and new != old_bk8:
                            parts[2] = new
                            it["rel_path"] = "/".join(parts)
                            it["body_key8"] = new
                            changed = True
                # subtitle / cover 若在同 (rid, old_bk8) 子目录下，随之一并改写
                for key in ("subtitle", "cover"):
                    val = it.get(key)
                    if isinstance(val, str) and val.startswith("resources/"):
                        nv = remap_rel(val, subdir_map)
                        if nv != val:
                            it[key] = nv
                            changed = True
                if changed:
                    touched += 1
    return data, touched


def run(downloads_dir, apply_):
    subdirs, subdir_map = discover(downloads_dir)
    to_migrate = [r for r in subdirs if r["has_media"] and r["old_bk8"] != r["new_bk8"]]
    no_media = [r for r in subdirs if not r["has_media"]]

    moves = plan_moves(subdirs)
    dedup_moves = [m for m in moves if m[2]]
    copy_moves = [m for m in moves if not m[2]]

    collections_file = os.path.join(downloads_dir, "_collections", "collections.json")
    new_data, touched_items = remap_collections(collections_file, subdir_map)

    # dry-run 也校验 remap 是否能对应上 collections 里的 (rid,bk8)
    print(f"[migrate_body_key8] downloads_dir = {downloads_dir}")
    print(f"  扫描子目录总数: {len(subdirs)}")
    print(f"  需迁移（内容哈希重排）: {len(to_migrate)}")
    print(f"  无媒体文件子目录（跳过）: {len(no_media)}")
    print(f"  计划移动文件: {len(moves)}  (去重删除 {len(dedup_moves)} / 改名保留 {len(copy_moves)})")
    print(f"  collections.json 待改写条目: {touched_items}")
    if not to_migrate and not moves and touched_items == 0:
        print("  ✅ 无需迁移：资源池已符合新公式。")
        return

    if not apply_:
        print("\n[dry-run] 未做任何改动。加 --apply 执行。预览前 20 条移动：")
        for src, dst, dedup in moves[:20]:
            tag = "DEDUP" if dedup else "MOVE "
            print(f"  [{tag}] {src}\n        -> {dst}")
        return

    # ---- 正式执行 ----
    print("\n[apply] 开始执行迁移 ...")
    reclaimed = 0
    for src, dst, dedup in moves:
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if dedup:
                sz = os.path.getsize(src)
                os.remove(src)
                reclaimed += sz
            else:
                if os.path.abspath(src) != os.path.abspath(dst):
                    shutil.move(src, dst)
        except OSError as e:
            print(f"  ⚠️ 移动失败 {src}: {e}")
    # 清理空旧子目录
    cleaned = 0
    for rec in to_migrate:
        old_dir = os.path.join(downloads_dir, "resources", rec["rid"], rec["old_bk8"])
        try:
            if os.path.isdir(old_dir) and not os.listdir(old_dir):
                os.rmdir(old_dir)
                cleaned += 1
        except OSError:
            pass

    # 写 collections.json（先备份）
    if new_data is not None:
        backup = collections_file + f".bak_{int(time.time())}"
        try:
            shutil.copy2(collections_file, backup)
            with open(collections_file, "w", encoding="utf-8") as f:
                json.dump(new_data, f, ensure_ascii=False, indent=2)
            print(f"  collections.json 已改写（备份: {backup}），受影响条目 {touched_items}")
        except Exception as e:
            print(f"  ⚠️ collections.json 写入失败: {e}；备份未动。")
    print(f"  去重回收空间约: {reclaimed/1024/1024:.1f} MB")
    print(f"  已清理空旧子目录: {cleaned}")
    print("  ✅ 迁移完成。建议重启 rm_app 使缓存失效并复核播放。")


def main():
    ap = argparse.ArgumentParser(description="RM 资源池 body_key8 内容派生迁移（O3 治本）")
    ap.add_argument("--downloads-dir", required=True,
                    help="RM 数据根目录（含 resources/ 与 _collections/），如 /home/fastgpt/media_data")
    ap.add_argument("--apply", action="store_true",
                    help="真正执行迁移；不加则仅 dry-run 预览")
    args = ap.parse_args()

    if not os.path.isdir(os.path.join(args.downloads_dir, "resources")):
        print(f"❌ 目录不存在或不含 resources/：{args.downloads_dir}", file=sys.stderr)
        sys.exit(1)

    if not args.apply:
        print("⚠️ dry-run 模式（不改动）。如确认无误，加 --apply 执行。")
    else:
        print("⚠️ 请确保 rm_app 已停止，避免并发写 collections.json。")
    run(args.downloads_dir, args.apply)


if __name__ == "__main__":
    main()
