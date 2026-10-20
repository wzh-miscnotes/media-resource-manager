# -*- coding: utf-8 -*-
"""import-dir 护栏回归测试（方案①）：
  - .processing / .failed 子目录应被跳过（不导入其内媒体）
  - {stem}.meta.json 不应被当 sidecar 污染资源池
  - 复制语义：源目录原封不动
  - 真实四件套（视频+字幕+封面）正常入池

隔离：在 import 前设 RM_DOWNLOADS_DIR 指向临时目录，避免污染项目 downloads。
"""
import os
import sys
import shutil
import tempfile
import hashlib

# 必须在 import app 前设置，config 在模块加载时即解析
_TMP = tempfile.mkdtemp(prefix="rm_import_guard_")
os.environ["RM_DOWNLOADS_DIR"] = _TMP
os.environ["RM_INBOX_DIR"] = os.path.join(_TMP, "inbox")
os.environ.setdefault("RM_AUTH_MODE", "standalone")

# 把项目根加入 sys.path，确保能 import app
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import app as rm_app  # noqa: E402

PASS, FAIL = 0, 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name} {detail}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {detail}")


def _make_file(p, content=b"x" * 1024):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(content)


def main():
    src = os.path.join(_TMP, "src")
    os.makedirs(src, exist_ok=True)
    stem = "demo_video"
    # 四件套（真实）
    _make_file(os.path.join(src, stem + ".mp4"))
    _make_file(os.path.join(src, stem + "_字幕.txt"), b"subtitle content")
    _make_file(os.path.join(src, stem + ".jpg"), b"cover bytes")
    _make_file(os.path.join(src, stem + ".meta.json"),
               b'{"owner":"admin@local","vid":"BVxxxxxx"}')
    # 干扰：.processing 半组 / .failed 已隔离
    _make_file(os.path.join(src, ".processing", "partial.mp4"))
    _make_file(os.path.join(src, ".failed", "broken.mp4"))

    # 调用 import_dir（直接传 sid 覆盖 Depends 默认值）
    req = rm_app.ImportDirReq(dir_path=src, user="admin@local", target_cid="default")
    res = rm_app.import_dir(req, sid="admin@local")
    print("import_dir 返回:", res)

    # 断言 1：added 恰好 = 1（仅真实视频，未把 .processing/.failed 的 mp4 算入）
    check("#1 .processing/.failed 被跳过",
          res["added"] == 1 and res["total"] == 1,
          f"added={res['added']} total={res['total']}")

    # 断言 2：资源池里无 .meta.json 脏文件
    resources_root = os.path.join(_TMP, "resources")
    meta_in_pool = []
    if os.path.isdir(resources_root):
        for _r, _d, fs in os.walk(resources_root):
            for f in fs:
                if f.endswith(".meta.json"):
                    meta_in_pool.append(os.path.join(_r, f))
    check("#2 meta.json 未污染资源池", len(meta_in_pool) == 0,
          f"found={meta_in_pool}")

    # 断言 3：复制语义——源目录所有原文件仍在（含 .processing/.failed/meta）
    src_after = set(os.path.relpath(os.path.join(r, f), src)
                    for r, _d, fs in os.walk(src) for f in fs)
    expected = {
        stem + ".mp4", stem + "_字幕.txt", stem + ".jpg", stem + ".meta.json",
        os.path.join(".processing", "partial.mp4"),
        os.path.join(".failed", "broken.mp4"),
    }
    check("#3 复制语义-源目录原封不动", src_after == expected,
          f"after={sorted(src_after)}")

    # 断言 4：字幕 + 封面已随视频入池（entry.subtitle 有值，cover 有值）
    cols = rm_app._sid_collections("admin@local")
    items = cols[0]["items"] if cols else []
    entry = items[0] if items else {}
    sub_ok = bool(entry.get("subtitle")) and entry.get("subtitle_source") == "official"
    cover_ok = bool(entry.get("cover"))
    check("#4 字幕(official)+封面入库", sub_ok and cover_ok,
          f"subtitle={entry.get('subtitle')} source={entry.get('subtitle_source')} cover={entry.get('cover')}")

    print(f"\n结果: PASS={PASS} FAIL={FAIL}")
    return FAIL == 0


if __name__ == "__main__":
    ok = main()
    # 清理临时目录
    try:
        shutil.rmtree(_TMP, ignore_errors=True)
    except Exception:
        pass
    sys.exit(0 if ok else 1)
