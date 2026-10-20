# -*- coding: utf-8 -*-
"""inbox watcher 验收自测（对照 _内部需求-inbox自动导入.md §3 七条）。

用法：
    set RM_* 环境变量由本脚本在 import app/config 之前注入，使用临时目录，
    不污染项目 downloads 与 inbox。运行：
    python scripts/test_inbox_watcher.py
"""
import os
import sys
import time
import json
import shutil
import tempfile
import hashlib

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---- 必须在 import app/config 之前注入配置 ----
TMP = tempfile.mkdtemp(prefix="rm_inbox_test_")
INBOX = os.path.join(TMP, "inbox")
DL = os.path.join(TMP, "downloads")
os.makedirs(INBOX, exist_ok=True)
os.makedirs(DL, exist_ok=True)

os.environ["RM_INBOX_DIR"] = INBOX
os.environ["RM_INBOX_POLL_SEC"] = "2"
os.environ["RM_INBOX_DEFAULT_OWNER"] = "admin@local"
os.environ["RM_INBOX_MAX_RETRY"] = "3"
os.environ["RM_DOWNLOADS_DIR"] = DL
os.environ["RM_AUTH_MODE"] = "standalone"
os.environ["RM_ADMIN_PASSWORD"] = "change-me-test-only"
os.environ["RM_SECRET"] = "change-me-test-only-secret"

sys.path.insert(0, HERE)
import inbox_watcher
from app import DOWNLOADS, RESOURCES_DIR, _sid_collections

results = []


def check(name, cond, extra=""):
    results.append((name, cond, extra))
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f"  -- {extra}" if extra else ""))


def rid_of(data: bytes) -> str:
    return "r" + hashlib.sha256(data).hexdigest()[:15]


def drop_group(stem, owner=None, subtitle=True, cover=True, meta=True, content=b"dummy mp4 bytes x" * 50):
    fp_video = os.path.join(INBOX, stem + ".mp4")
    with open(fp_video, "wb") as f:
        f.write(content)
    if subtitle:
        with open(os.path.join(INBOX, stem + "_字幕.txt"), "w", encoding="utf-8") as f:
            f.write("1\n00:00:00,000 --> 00:00:02,000\n测试字幕\n")
    if cover:
        with open(os.path.join(INBOX, stem + ".jpg"), "wb") as f:
            f.write(b"\xff\xd8\xff\xe0jpgdummy" * 10)
    if meta:
        m = {"vid": "BVxxxxxx", "title": stem, "quality_id": "80", "source": "official",
             "owner": owner or "admin@local", "delivered_at": time.time()}
        with open(os.path.join(INBOX, stem + ".meta.json"), "w", encoding="utf-8") as f:
            json.dump(m, f, ensure_ascii=False)
    return fp_video


def wait_for(pred, timeout=30, interval=0.5):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if pred():
            return True
        time.sleep(interval)
    return False


def inbox_empty_of_groups():
    left = [f for f in os.listdir(INBOX)
            if not f.startswith(".") and os.path.isfile(os.path.join(INBOX, f))]
    return len(left) == 0


def count_resource_dirs():
    if not os.path.isdir(RESOURCES_DIR):
        return 0
    return len([d for d in os.listdir(RESOURCES_DIR) if os.path.isdir(os.path.join(RESOURCES_DIR, d))])


def main():
    inbox_watcher.start_inbox_watcher()
    time.sleep(1)  # 让线程起来

    # ---------- #1 四件套（含 meta.owner） ----------
    stem1 = "测试视频 [BVxxxxxx]"
    content1 = os.urandom(4096)
    expected_rid1 = rid_of(content1)
    drop_group(stem1, owner="admin@local", content=content1)
    ok1 = wait_for(lambda: any(it.get("resource_id") == expected_rid1
                               for it in _sid_collections("admin@local")[0]["items"]), timeout=30)
    check("#1 四件套入池(rid=内容哈希)", ok1, f"expected_rid={expected_rid1}")
    item1 = next((it for it in _sid_collections("admin@local")[0]["items"]
                  if it.get("resource_id") == expected_rid1), None)

    # ---------- #3 inbox 清洁 ----------
    ok3 = wait_for(inbox_empty_of_groups, timeout=30)
    check("#3 inbox 处理即清(无堆积)", ok3, f"left={os.listdir(INBOX)}")

    # ---------- #2 字幕绑定 subtitle_source=official ----------
    ok2 = bool(item1) and item1.get("subtitle_source") == "official" and bool(item1.get("subtitle"))
    check("#2 字幕绑定 subtitle_source=official", ok2,
          f"subtitle_source={item1.get('subtitle_source') if item1 else None}, subtitle={item1.get('subtitle') if item1 else None}")

    # ---------- B2 封面入库 ----------
    ok_cover = bool(item1) and bool(item1.get("cover")) and item1.get("cover", "").lower().endswith((".jpg", ".png", ".jpeg", ".webp"))
    check("B2 封面入库(entry.cover 有值)", ok_cover, f"cover={item1.get('cover') if item1 else None}")

    # ---------- #4 重复投放同一内容（同文件名）→ dedup ----------
    # 注意：既有 _ingest_into_pool 去重键 = resources/<rid>/<body_key8>，
    # body_key8 = sha256(文件名|大小)；故「同内容」须同文件名才命中 dedup（生产同 BV 文件名稳定）。
    n_before = count_resource_dirs()
    drop_group(stem1, owner="admin@local", content=content1)  # 与 #1 完全相同（同内容+同文件名）
    ok4 = wait_for(lambda: count_resource_dirs() == n_before, timeout=30)
    # 资源目录数不变即未涨副本（dedup_hit）
    check("#4 重复内容不涨副本(dedup_hit)", count_resource_dirs() == n_before,
          f"dirs_before={n_before} dirs_after={count_resource_dirs()}")

    # ---------- #5 中途崩溃重启续跑（.processing 残留） ----------
    stem5 = "崩溃恢复视频 [BVxxxxxx]"
    content5 = os.urandom(4096)
    expected_rid5 = rid_of(content5)
    proc5 = os.path.join(INBOX, ".processing", stem5)
    os.makedirs(proc5, exist_ok=True)
    with open(os.path.join(proc5, stem5 + ".mp4"), "wb") as f:
        f.write(content5)
    with open(os.path.join(proc5, stem5 + "_字幕.txt"), "w", encoding="utf-8") as f:
        f.write("x")
    with open(os.path.join(proc5, stem5 + ".meta.json"), "w", encoding="utf-8") as f:
        json.dump({"owner": "admin@local", "title": stem5}, f, ensure_ascii=False)
    ok5 = wait_for(lambda: any(it.get("resource_id") == expected_rid5
                               for it in _sid_collections("admin@local")[0]["items"]), timeout=30)
    check("#5 崩溃恢复(.processing 残留续跑)", ok5, f"expected_rid={expected_rid5}")

    # ---------- #6 无 meta 孤立视频（默认 owner + 降级日志） ----------
    stem6 = "孤立视频无meta [BVxxxxxx]"
    content6 = os.urandom(4096)
    expected_rid6 = rid_of(content6)
    fp6 = os.path.join(INBOX, stem6 + ".mp4")
    with open(fp6, "wb") as f:
        f.write(content6)
    # 绕过年龄护栏：把 mtime 设为 60s 前
    old = time.time() - 60
    os.utime(fp6, (old, old))
    ok6 = wait_for(lambda: any(it.get("resource_id") == expected_rid6
                               for it in _sid_collections("admin@local")[0]["items"]), timeout=30)
    check("#6 无meta孤立视频→默认owner导入", ok6, f"expected_rid={expected_rid6}")

    # ---------- #7 连续失败组 → .failed 且隔离 ----------
    # 临时让 watcher 的入池函数必抛异常
    real_ingest = inbox_watcher._ingest_into_pool

    def _boom(*a, **k):
        raise RuntimeError("injected failure")
    inbox_watcher._ingest_into_pool = _boom
    stem7 = "必失败视频 [BVxxxxxx]"
    drop_group(stem7, owner="admin@local", content=os.urandom(4096))
    ok7_failed = wait_for(lambda: os.path.isdir(os.path.join(INBOX, ".failed", stem7)), timeout=30)
    # 隔离：之后再丢一个正常组，应照常入池（不受 #7 阻塞）
    inbox_watcher._ingest_into_pool = real_ingest
    stem7b = "隔离验证视频 [BVxxxxxx]"
    content7b = os.urandom(4096)
    expected_rid7b = rid_of(content7b)
    drop_group(stem7b, owner="admin@local", content=content7b)
    ok7_iso = wait_for(lambda: any(it.get("resource_id") == expected_rid7b
                                   for it in _sid_collections("admin@local")[0]["items"]), timeout=30)
    check("#7 连续失败→.failed且不阻塞后续", ok7_failed and ok7_iso,
          f"failed_exists={ok7_failed}, isolated_ok={ok7_iso}")

    # 汇总
    passed = sum(1 for _, c, _ in results if c)
    print(f"\n==== 自测结果: {passed}/{len(results)} 通过 ====")
    # 清理临时目录
    try:
        shutil.rmtree(TMP, ignore_errors=True)
    except Exception:
        pass
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
