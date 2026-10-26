#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
O7 并发压测：多用户并发回收站 / 共享健壮性验证。

验证目标（均走真实 app.py 内部函数，非 HTTP）：
  A) 同 rid 多引用并发删除 -> 回收站该 rid 恰好 1 条（无重复回收站条目），且引用全清；
  B) 同内容并发入池 -> 合集该条目恰好 1 条（无重复条目）；
  C) 共享令牌 locked 并发切换 -> 终态合法（locked => revoked），无 json 损坏 / 无异常；
  D) 多进程模式（仅 posix / fcntl 可用时）-> 两进程各 N 次写，终态 = 2N，无丢更新。

说明：本机若为 Windows，_FCNTL=False，文件锁为无操作，D 自动跳过；
      单进程场景 A/B/C 依赖「单进程共享缓存 + 事务」保证，验证当前部署形态下的健壮性。
      D（跨进程丢更新）需在 Linux 部署（flock 可用）运行以验证文件锁修复。
"""
import os
import sys
import json
import shutil
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import app as rm  # noqa: E402

TMP = tempfile.mkdtemp(prefix="rm_stress_")
rm.DOWNLOADS = TMP
rm.COLLECTIONS_DIR = os.path.join(TMP, "_collections")
rm.SHARES_DIR = os.path.join(TMP, "_collections")
rm.COLLECTIONS_FILE = os.path.join(rm.COLLECTIONS_DIR, "collections.json")
rm.SHARES_FILE = os.path.join(rm.SHARES_DIR, "shares.json")
rm.RESOURCES_DIR = os.path.join(TMP, "resources")
rm.THUMBNAIL_CACHE_DIR = os.path.join(TMP, ".thumbnail_cache")
rm._COLLECTIONS_LOCKFILE = os.path.join(rm.COLLECTIONS_DIR, ".collections.lock")
rm._SHARES_LOCKFILE = os.path.join(rm.SHARES_DIR, ".shares.lock")


def fresh_state():
    for p in (rm.COLLECTIONS_FILE, rm.SHARES_FILE):
        try:
            os.remove(p)
        except OSError:
            pass
    rm._collections_cache = None
    rm._shares_cache = None
    rm._collections_mtime = None
    rm._shares_mtime = None


def trash_items_for(rid):
    data = rm._load_collections()
    trash = data.get("admin@local", {}).get("collections", [])
    trash = next((c for c in trash if c.get("id") == "__trash__"), None)
    if not trash:
        return []
    return [it for it in trash["items"]
            if (it.get("resource_id") or "") == rid]


def count_all_refs(rid):
    n = 0
    data = rm._load_collections()
    for owner, v in data.items():
        for c in v.get("collections", []):
            if c.get("id") == "__trash__":
                continue
            for it in c.get("items", []):
                if (it.get("resource_id") or "") == rid:
                    n += 1
    return n


# ---- 场景 A：同 rid 多引用并发删除，回收站应恰好 1 条 ----
def scenario_a():
    rid = "rA" + "0" * 13
    K = 50
    cycles = 40
    for cyc in range(cycles):
        fresh_state()
        # 建 K 个引用：分到 K 个不同 owner（跨 owner 不互删），各自 1 条，resource_id 同为 rid
        for i in range(K):
            entry = {
                "rel_path": "resources/%s/b1/file%d.mp4" % (rid, i),
                "resource_id": rid, "title": "t", "vid": "v", "seq": "01",
            }
            rm._add_to_collection("uA%d" % i, entry, "default")
        assert count_all_refs(rid) == K, "setup refs != K: %d" % count_all_refs(rid)

        def delete_one(i):
            owner = "uA%d" % i
            with rm._collections_txn():
                data = rm._load_collections()
                cols = data.get(owner, {}).get("collections", [])
                for c in cols:
                    if c.get("id") == "default":
                        rp = "resources/%s/b1/file%d.mp4" % (rid, i)
                        before = len(c["items"])
                        c["items"] = [it for it in c["items"] if it.get("rel_path") != rp]
                        if len(c["items"]) != before:
                            rm._save_collections()
                if rm.count_active_refs(rid) == 0:
                    rm.ensure_trash_entry(rid, "t", owner, "resources/%s/" % rid)

        with ThreadPoolExecutor(max_workers=K) as ex:
            list(ex.map(delete_one, range(K)))

        # 断言：引用全清 + 回收站该 rid 恰好 1 条
        assert count_all_refs(rid) == 0, "refs not cleared: %d" % count_all_refs(rid)
        t = trash_items_for(rid)
        assert len(t) == 1, "trash entries for rid=%d, expected 1" % len(t)
    return cycles


# ---- 场景 B：同内容（同 rel_path）并发入池，合集应恰好 1 条 ----
def scenario_b():
    rid = "rB" + "0" * 13
    M = 50
    cycles = 40
    for cyc in range(cycles):
        fresh_state()
        owner = "uB%d" % cyc

        def add_one(_):
            entry = {
                "rel_path": "resources/%s/b1/file.mp4" % rid,
                "resource_id": rid, "title": "t", "vid": "v", "seq": "01",
            }
            rm._add_to_collection(owner, entry, "default")

        with ThreadPoolExecutor(max_workers=M) as ex:
            list(ex.map(add_one, range(M)))

        data = rm._load_collections()
        items = data.get(owner, {}).get("collections", [{}])[0].get("items", [])
        assert len(items) == 1, "collection items=%d, expected 1" % len(items)
    return cycles


# ---- 场景 C：共享 locked 并发切换，终态必须合法 ----
def scenario_c():
    owner, rid = "uC", "rC" + "0" * 13
    # 预置一个令牌
    fresh_state()
    tok = "tokC"
    sd = rm._load_shares()
    sd.setdefault("tokens", {})[tok] = {
        "token": tok, "owner": owner, "resource_id": rid,
        "revoked": False, "locked": False,
    }
    rm._save_shares()

    N = 200

    def toggle(i):
        if i % 2 == 0:
            rm._lock_owner_shares(owner, rid)
        else:
            rm._unlock_owner_shares(owner, rid)

    with ThreadPoolExecutor(max_workers=20) as ex:
        list(ex.map(toggle, range(N)))

    sd = rm._load_shares()
    rec = sd["tokens"][tok]
    # 合法不变量：locked => revoked；且字段均为布尔
    assert isinstance(rec["locked"], bool) and isinstance(rec["revoked"], bool)
    assert (rec["locked"] is True) == (rec["revoked"] is True and rec["locked"] is True)
    # 文件仍可解析（无损坏）
    with open(rm.SHARES_FILE, encoding="utf-8") as f:
        json.load(f)
    return N


# ---- 场景 D：多进程（仅 fcntl 可用时）----
# 关键：每条 entry 用全局唯一 (vid,seq,title) 去重键，避免合集去重把不同条目合并；
# 终态应为 2N（两进程各 N 条唯一条目）。若跨进程无锁保护，并发 RMW 会丢更新 → < 2N。
def scenario_d():
    if not rm._FCNTL:
        return None
    import subprocess
    rid = "rD" + "0" * 13
    N = 100
    script = os.path.join(TMP, "_d_worker.py")
    worker_src = (
        "import sys, os\n"
        "idx = int(sys.argv[1]) if len(sys.argv) > 1 else 0\n"
        "N = %d\n"
        "sys.path.insert(0, %r)\n"
        "import app as rm\n"
        "rm.DOWNLOADS=%r\n"
        "rm.COLLECTIONS_DIR=%r\n"
        "rm.SHARES_DIR=%r\n"
        "rm.COLLECTIONS_FILE=%r\n"
        "rm.RESOURCES_DIR=%r\n"
        "rm._COLLECTIONS_LOCKFILE=%r\n"
        "rm._collections_cache=None; rm._collections_mtime=None\n"
        "rid=%r; base=idx*N\n"
        "for i in range(N):\n"
        "    k = base + i\n"
        "    e = {'rel_path': 'resources/rD/b1/f%%d.mp4' %% k,\n"
        "         'resource_id': rid, 'title': 't%%d' %% k, 'vid': 'v', 'seq': '%%04d' %% k}\n"
        "    rm._add_to_collection('uD', e, 'default')\n"
        % (N, ROOT, TMP, rm.COLLECTIONS_DIR, rm.SHARES_DIR, rm.COLLECTIONS_FILE,
           rm.RESOURCES_DIR, rm._COLLECTIONS_LOCKFILE, rid)
    )
    with open(script, "w", encoding="utf-8") as f:
        f.write(worker_src)
    fresh_state()
    procs = [subprocess.Popen([sys.executable, script, str(p)]) for p in range(2)]
    for p in procs:
        assert p.wait() == 0, "worker exit nonzero"
    data = rm._load_collections()
    items = data.get("uD", {}).get("collections", [{}])[0].get("items", [])
    # 两进程各 N 条唯一条目，理想 = 2N；有跨进程文件锁保护不应丢更新
    assert len(items) == 2 * N, "multi-proc items=%d, expected %d（跨进程锁可能未生效）" % (len(items), 2 * N)
    return 2 * N


if __name__ == "__main__":
    fails = []
    try:
        ca = scenario_a()
        print("[PASS] 场景A 回收站并发去重 (%d 轮)" % ca)
    except AssertionError as e:
        fails.append(("A", str(e)))
        print("[FAIL] 场景A: %s" % e)
    try:
        cb = scenario_b()
        print("[PASS] 场景B 入池并发去重 (%d 轮)" % cb)
    except AssertionError as e:
        fails.append(("B", str(e)))
        print("[FAIL] 场景B: %s" % e)
    try:
        cc = scenario_c()
        print("[PASS] 场景C 共享 locked 并发 (%d 次切换)" % cc)
    except AssertionError as e:
        fails.append(("C", str(e)))
        print("[FAIL] 场景C: %s" % e)
    try:
        cd = scenario_d()
        if cd is None:
            print("[SKIP] 场景D 多进程（本机无 fcntl，需在 Linux 部署验证文件锁）")
        else:
            print("[PASS] 场景D 多进程无丢更新 (%d 条)" % cd)
    except AssertionError as e:
        fails.append(("D", str(e)))
        print("[FAIL] 场景D: %s" % e)

    shutil.rmtree(TMP, ignore_errors=True)
    if fails:
        print("\n结果：FAIL (%d 项未通过)" % len(fails))
        sys.exit(1)
    print("\n结果：ALL PASS")
    sys.exit(0)
