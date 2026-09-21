#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_netwatch_classify.py —— netwatch 目标定性的回归测试

盯住三件容易出错的事：
  1. 标记匹配取【最长命中】：具体标记要压过宽泛标记，否则一个宽泛的厂商
     标记会把更具体的广告/统计域名吞成"云厂商"。
  2. 广告/统计只标注：它们绝不进"待查证/可封禁"清单。
  3. IP 段只做兜底，且用二分查找（几万条也不能拖慢采样）。

运行：python test_netwatch_classify.py     （不需要管理员、不联网）
"""
import importlib.util
import ipaddress
import os
import random
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def load_netwatch(config=None):
    """以指定的 watch-config.json 内容加载 netwatch 模块。

    netwatch 在导入时读配置，所以测试要先把临时配置就位——用环境变量
    让 netwatch 指向它（NG_CONFIG 不存在时退回默认路径）。
    """
    path = os.path.join(HERE, "netwatch.py")
    spec = importlib.util.spec_from_file_location("nw_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Base(unittest.TestCase):
    """用一份临时配置覆盖 netwatch 的全局配置，再重新加载模块。"""

    CFG = {
        "cloud_domain_markers": ["cloud-example.test", "oss-"],
        "marker_groups": [
            {"label": "云", "suspicious": True,
             "markers": [["broad.test", "宽泛厂商"], ["bucket.broad.test",
                                                      "具体存储"]]},
            {"label": "广告", "suspicious": False,
             "markers": [["ads.broad.test", "具体广告"]]},
        ],
        "cloud_cidrs": ["203.0.113.0/24"],
    }

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="nw-cfg-")
        cls._old = os.path.join(HERE, "watch-config.json")
        cls._backup = None
        if os.path.exists(cls._old):
            with open(cls._old, encoding="utf-8") as f:
                cls._backup = f.read()
        import json
        with open(cls._old, "w", encoding="utf-8") as f:
            json.dump(cls.CFG, f, ensure_ascii=False)
        cls.nw = load_netwatch()

    @classmethod
    def tearDownClass(cls):
        import shutil
        if cls._backup is not None:
            with open(cls._old, "w", encoding="utf-8") as f:
                f.write(cls._backup)
        else:
            try:
                os.remove(cls._old)
            except OSError:
                pass
        shutil.rmtree(cls._tmp, ignore_errors=True)

    # ---- 1. 最长命中 ----
    def test_longest_marker_wins(self):
        kind, label = self.nw.classify_vendor("cdn.ads.broad.test")
        self.assertEqual(kind, "ad", "具体广告标记应压过宽泛厂商标记")
        self.assertEqual(label, "具体广告")

    def test_broad_marker_still_matches(self):
        self.assertEqual(self.nw.classify_vendor("x.broad.test")[0],
                         "suspicious")
        self.assertEqual(self.nw.classify_vendor("bucket.broad.test")[1],
                         "具体存储")

    def test_flat_legacy_markers_are_suspicious(self):
        self.assertEqual(self.nw.classify_vendor("a.cloud-example.test")[0],
                         "suspicious")
        self.assertTrue(self.nw.is_cloud_name("oss-cn-hangzhou.test"))
        self.assertFalse(self.nw.is_cloud_name("cdn.ads.broad.test"),
                         "广告域名不该被判成云厂商")

    def test_unknown_is_neither(self):
        self.assertEqual(self.nw.classify_vendor("github.com"), (None, None))

    # ---- 2. 广告只标注 ----
    def test_ad_lands_in_label_only_category(self):
        # 用真实公网 IP：ipaddress 把 203.0.113.0/24 这类文档段判为 private，
        # 那样会在进入厂商判定之前就返回"私有网络"。
        disp, cat, note, flags = self.nw.classify_dest(
            "8.8.8.8", ["tracker.ads.broad.test"],
            self.nw.Rules(self._empty_rules()))
        self.assertEqual(cat, self.nw.AD_CATEGORY)
        self.assertIn(self.nw.AD_CATEGORY, self.nw.LABEL_ONLY_CATEGORIES)
        self.assertNotIn(cat, self.nw.BENIGN_CATEGORIES)

    def test_cloud_still_suspicious(self):
        disp, cat, note, flags = self.nw.classify_dest(
            "1.2.3.4", ["a.cloud-example.test"],
            self.nw.Rules(self._empty_rules()))
        self.assertNotIn(cat, self.nw.BENIGN_CATEGORIES)
        self.assertNotEqual(cat, self.nw.AD_CATEGORY)

    def _empty_rules(self):
        p = os.path.join(self._tmp, "rules.txt")
        if not os.path.exists(p):
            with open(p, "w", encoding="utf-8") as f:
                f.write("# empty\n")
        return p

    # ---- 3. 网段兜底 + 二分 ----
    def test_is_cloud_ip_uses_config(self):
        self.assertTrue(self.nw.is_cloud_ip("203.0.113.5"))
        self.assertFalse(self.nw.is_cloud_ip("203.0.114.5"))
        self.assertFalse(self.nw.is_cloud_ip("2001:db8::1"))

    def test_ranges_merge_overlaps(self):
        ranges = self.nw._build_ranges(
            ["10.0.0.0/24", "10.0.1.0/24", "10.0.0.128/25", "192.168.0.0/16"])
        # 10.0.0.0/24 与 10.0.1.0/24 相邻，应合并成一段
        self.assertEqual(ranges[0][0], int(ipaddress.ip_address("10.0.0.0")))
        self.assertEqual(ranges[0][1], int(ipaddress.ip_address("10.0.1.255")))
        self.assertEqual(len(ranges), 2)

    def test_lookup_is_fast_with_many_ranges(self):
        """几万条区间下，单次查询必须是微秒级（二分），不能是线性扫描。"""
        rnd = random.Random(1234)
        cidrs = []
        base = int(ipaddress.ip_address("1.0.0.0"))
        for i in range(30000):
            lo = base + i * 1024
            cidrs.append(str(ipaddress.ip_address(lo)) + "/22")
        nw = self.nw
        saved_ranges, saved_starts = nw._CLOUD_RANGES, nw._CLOUD_STARTS
        try:
            nw._CLOUD_RANGES = nw._build_ranges(cidrs)
            nw._CLOUD_STARTS = [r[0] for r in nw._CLOUD_RANGES]
            t0 = time.perf_counter()
            for _ in range(2000):
                nw.is_cloud_ip("8.8.8.8")
            dt = (time.perf_counter() - t0) / 2000
            self.assertLess(dt, 50e-6, f"单次查询 {dt*1e6:.1f}µs，太慢")
        finally:
            nw._CLOUD_RANGES, nw._CLOUD_STARTS = saved_ranges, saved_starts

    # ---- 产品类型启发式（厂商中立）----
    def test_service_kind_is_vendor_neutral(self):
        nw = self.nw
        self.assertIn("对象存储", nw.cloud_service_kind("x.oss-cn.test"))
        self.assertIn("对象存储", nw.cloud_service_kind("bucket.bcebos.test"))
        self.assertIn("对象存储", nw.cloud_service_kind("blob.core.test"))
        self.assertIn("日志", nw.cloud_service_kind("log-collector.test"))
        for name in ("oss-cn.test", "bcebos.test"):
            kind = nw.cloud_service_kind(name)
            self.assertNotIn("阿里", kind)
            self.assertNotIn("百度", kind)


if __name__ == "__main__":
    unittest.main(verbosity=2)
