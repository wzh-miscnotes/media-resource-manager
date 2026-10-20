# -*- coding: utf-8 -*-
"""O3 治本回归测试：
  Part A — 内容级去重：同内容、不同文件名两次入池，应命中 dedup_hit 且物理只存一份。
  Part B — 迁移脚本：合成 resources 树（同内容两子目录 + 不同内容一子目录）+ collections.json，
           验证 dry-run 不改、--apply 后合并去重、collections 条目改写。

隔离：import app 前设 RM_DOWNLOADS_DIR 指向临时目录。
"""
import os
import sys
import shutil
import tempfile
import json
import hashlib

_TMP = tempfile.mkdtemp(prefix="rm_o3_")
os.environ["RM_DOWNLOADS_DIR"] = _TMP
os.environ["RM_INBOX_DIR"] = os.path.join(_TMP, "inbox")
os.environ.setdefault("RM_AUTH_MODE", "standalone")

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "scripts"))

import app as rm_app  # noqa: E402
import migrate_body_key8 as mig  # noqa: E402

PASS, FAIL = 0, 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name} {detail}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {detail}")


def _write(p, content):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(content)


def _count_media(dir_):
    if not os.path.isdir(dir_):
        return 0
    return sum(1 for f in os.listdir(dir_)
               if f.lower().endswith(rm_app.MEDIA_EXT))


def part_a():
    print("\n=== Part A: 内容级去重（同内容不同文件名只存一份）===")
    stage = os.path.join(_TMP, "_staging_a")
    content = b"MEDIA-CONTENT-XYZ-1234567890" * 5000  # 一条稳定内容
    f1 = os.path.join(stage, "first_name.mp4")
    f2 = os.path.join(stage, "second_name_different.mp4")  # 同内容、不同文件名
    _write(f1, content)
    _write(f2, content)

    h = rm_app._sha256_of_file(f1)
    rid = "r" + h[:15]
    bk8 = rm_app._body_key8_from_hash(h)

    r1, d1, _ = rm_app._ingest_into_pool(
        "admin@local", rid, bk8, f1, [], "t1", content_sha256=h)
    r2, d2, _ = rm_app._ingest_into_pool(
        "admin@local", rid, bk8, f2, [], "t2", content_sha256=h)

    pool_dir = os.path.join(_TMP, "resources", rid, bk8)
    n_media = _count_media(pool_dir)

    check("A1 首次入池 dedup_hit=False", d1 is False, f"d1={d1}")
    check("A2 同内容二次入池 dedup_hit=True", d2 is True, f"d2={d2}")
    check("A3 物理仅存 1 份（不同文件名不重复占盘）", n_media == 1, f"media_count={n_media}")
    # 反向证明：旧公式 sha256(文件名|大小) 会因文件名不同而不同（即旧逻辑才会存两份）；
    # 新公式（内容派生）对同内容恒等，与文件名无关。
    old_bk8a = hashlib.sha256(b"first_name.mp4" + ("|%d" % len(content)).encode()).hexdigest()[:8]
    old_bk8b = hashlib.sha256(b"second_name_different.mp4" + ("|%d" % len(content)).encode()).hexdigest()[:8]
    new_a = rm_app._body_key8_from_hash(h)
    new_b = rm_app._body_key8_from_hash(h)  # 同内容 → 同一哈希 → 同一 bk8
    check("A4 旧公式按文件名区分 bk8（旧逻辑才会存两份）；新公式同内容恒等",
          old_bk8a != old_bk8b and new_a == new_b, f"old_a={old_bk8a} old_b={old_bk8b} new={new_a}")

    # 不同内容应分别存储（不误并）
    stage2 = os.path.join(_TMP, "_staging_a2")
    content_y = b"DIFFERENT-CONTENT-AAA" * 5000
    fy = os.path.join(stage2, "other.mp4")
    _write(fy, content_y)
    hy = rm_app._sha256_of_file(fy)
    rid_y = "r" + hy[:15]
    bk8_y = rm_app._body_key8_from_hash(hy)
    _, dy, _ = rm_app._ingest_into_pool(
        "admin@local", rid_y, bk8_y, fy, [], "ty", content_sha256=hy)
    pool_y = os.path.join(_TMP, "resources", rid_y, bk8_y)
    check("A5 不同内容独立存储（dy=False, 各 1 份）",
          dy is False and _count_media(pool_y) == 1, f"dy={dy}")


def part_b():
    print("\n=== Part B: 迁移脚本 合并 + 改写 collections ===")
    data_dir = os.path.join(_TMP, "mig")
    res_dir = os.path.join(data_dir, "resources")
    col_dir = os.path.join(data_dir, "_collections")
    os.makedirs(col_dir, exist_ok=True)

    rid = "rCONTENTHASHPLACEHOLDER001"
    old1, old2, old3 = "AAAA1111", "BBBB2222", "CCCC3333"
    content_x = b"X" * 8000
    content_y = b"Y" * 8000

    _write(os.path.join(res_dir, rid, old1, "A.mp4"), content_x)
    _write(os.path.join(res_dir, rid, old2, "A.mp4"), content_x)  # 同内容 X
    _write(os.path.join(res_dir, rid, old3, "B.mp4"), content_y)  # 不同内容 Y

    collections = {
        "admin@local": {"collections": [{"id": "default", "name": "默认合集", "items": [
            {"rel_path": f"resources/{rid}/{old1}/A.mp4", "body_key8": old1, "resource_id": rid, "subtitle": "", "cover": ""},
            {"rel_path": f"resources/{rid}/{old2}/A.mp4", "body_key8": old2, "resource_id": rid, "subtitle": "", "cover": ""},
            {"rel_path": f"resources/{rid}/{old3}/B.mp4", "body_key8": old3, "resource_id": rid, "subtitle": "", "cover": ""},
        ]}]}
    }
    col_file = os.path.join(col_dir, "collections.json")
    with open(col_file, "w", encoding="utf-8") as f:
        json.dump(collections, f)

    # dry-run：不应改动任何文件
    mig.run(data_dir, apply_=False)
    check("B1 dry-run 后旧子目录仍在",
          os.path.isdir(os.path.join(res_dir, rid, old1)) and
          os.path.isdir(os.path.join(res_dir, rid, old2)) and
          os.path.isdir(os.path.join(res_dir, rid, old3)),
          "")
    with open(col_file, encoding="utf-8") as f:
        check("B2 dry-run 后 collections 内容未变", json.load(f) == collections, "")

    # apply
    mig.run(data_dir, apply_=True)
    # 计算规范 new bk8
    hx = hashlib.sha256(content_x).hexdigest()
    hy = hashlib.sha256(content_y).hexdigest()
    new_x = hx[mig._BODY_KEY8_WIN]
    new_y = hy[mig._BODY_KEY8_WIN]

    check("B3 同内容两子目录已合并为 new_x 且只 1 份",
          _count_media(os.path.join(res_dir, rid, new_x)) == 1,
          f"new_x={new_x}")
    check("B4 不同内容保留为 new_y 且只 1 份",
          _count_media(os.path.join(res_dir, rid, new_y)) == 1,
          f"new_y={new_y}")
    check("B5 旧子目录已清理",
          not os.path.isdir(os.path.join(res_dir, rid, old1)) and
          not os.path.isdir(os.path.join(res_dir, rid, old2)) and
          not os.path.isdir(os.path.join(res_dir, rid, old3)),
          "")
    with open(col_file, encoding="utf-8") as f:
        after = json.load(f)
    items = after["admin@local"]["collections"][0]["items"]
    rp_set = {it["rel_path"] for it in items}
    bk_set = {it["body_key8"] for it in items}
    check("B6 collections 条目已改写到 new_x/new_y",
          all(p.startswith(f"resources/{rid}/{new_x}") or p.startswith(f"resources/{rid}/{new_y}") for p in rp_set),
          f"rel_paths={rp_set}")
    check("B7 body_key8 已更新", new_x in bk_set and new_y in bk_set and old1 not in bk_set,
          f"bk_set={bk_set}")


def main():
    part_a()
    part_b()
    print(f"\n结果: PASS={PASS} FAIL={FAIL}")
    return FAIL == 0


if __name__ == "__main__":
    ok = main()
    try:
        shutil.rmtree(_TMP, ignore_errors=True)
    except Exception:
        pass
    sys.exit(0 if ok else 1)
