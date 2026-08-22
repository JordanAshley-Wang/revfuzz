"""RevFuzz 主循环 —— P1（组长）负责。

设计原则：依赖接口而非实现。
- P3 提供 CoverageRunner.run(bytes) -> RunResult
- P4 提供 mutate / pick_seed
- P5 提供 classify_crash

P4/P5 未就绪前由内置极简兜底顶替（捕获 NotImplementedError），
保证主循环在 D2~D4 期间可独立自测；D5 集成时逐一切换为真实实现。
"""
from __future__ import annotations

import hashlib
import logging
import os
import random
import time

from contract import CampaignStats, CrashInfo, RunResult, Seed
from engine.coverage import CoverageRunner
from engine.mutator import mutate as _p4_mutate
from engine.scheduler import pick_seed as _p4_pick
from engine.triage import classify_crash as _p5_classify

LOG = logging.getLogger("revfuzz.fuzzer")

_LOG_INTERVAL_S = 60  # 运行中每 60 秒打一条 INFO 进度


class Fuzzer:
    """覆盖引导 fuzzing 主循环。"""

    def __init__(
        self,
        target: str,
        corpus: list[str] | None = None,
        dictionary: list[bytes] | None = None,
        analysis: dict | None = None,
        workdir: str = "out",
        timeout_s: int = 3600,
        max_len: int = 4096,
        max_execs: int | None = None,
        coverage_runner: CoverageRunner | None = None,
        seed_rng: int | None = None,
    ) -> None:
        self.target = target
        self.analysis = analysis or {}
        self.dictionary = dictionary or []
        self.workdir = workdir
        self.timeout_s = timeout_s
        self.max_len = max_len
        self.max_execs = max_execs
        self.coverage = coverage_runner or CoverageRunner(target)
        self._rng = random.Random(seed_rng)

        self.queue_dir = os.path.join(workdir, "queue")
        self.crash_dir = os.path.join(workdir, "crashes")
        os.makedirs(self.queue_dir, exist_ok=True)
        os.makedirs(self.crash_dir, exist_ok=True)

        self.queue: list[Seed] = self._load_corpus(corpus or [])
        self.unique_edges: set[int] = set()
        self.crashes: list[CrashInfo] = []
        self._dedup: set[str] = set()

        self.total_execs = 0
        self.total_crashes = 0
        self.total_timeouts = 0

    # ---------------- 主循环 ----------------

    def run(self) -> CampaignStats:
        """跑到 timeout_s（或 max_execs，供测试用）为止，返回汇总统计。"""
        LOG.info("fuzzing start: target=%s seeds=%d dict=%d timeout=%ds",
                 self.target, len(self.queue), len(self.dictionary), self.timeout_s)
        start = time.time()
        deadline = start + self.timeout_s
        last_log = start

        while time.time() < deadline:
            if self.max_execs is not None and self.total_execs >= self.max_execs:
                break
            seed = self._pick()
            data = self._mutate(seed.data)
            try:
                result = self.coverage.run(data)
            except NotImplementedError:
                LOG.error("CoverageRunner 未就绪（P3 关键路径），主循环退出")
                break
            self._step(data, result)

            now = time.time()
            if now - last_log >= _LOG_INTERVAL_S:
                LOG.info("execs=%d edges=%d crashes=%d(unique=%d) queue=%d",
                         self.total_execs, len(self.unique_edges),
                         self.total_crashes, len(self.crashes), len(self.queue))
                last_log = now

        stats = self._make_stats(start)
        LOG.info("fuzzing done: execs=%d unique_crashes=%d edges=%d",
                 stats.total_execs, stats.unique_crashes, stats.edges_covered)
        return stats

    # ---------------- 单轮处理 ----------------

    def _step(self, data: bytes, result: RunResult) -> None:
        self.total_execs += 1
        self.unique_edges |= result.edges
        if result.is_new:
            self._enqueue(data, result)
        if result.status == "crash":
            self._handle_crash(data, result)
        elif result.status == "timeout":
            self.total_timeouts += 1

    def _pick(self) -> Seed:
        try:
            seed = _p4_pick(self.queue, self.analysis)
        except NotImplementedError:
            seed = self._rng.choice(self.queue)  # 兜底：均匀随机（P4 就绪后移除）
        seed.exec_count += 1
        return seed

    def _mutate(self, data: bytes) -> bytes:
        try:
            return _p4_mutate(data, self.dictionary, self.max_len)
        except NotImplementedError:
            return self._fallback_mutate(data)  # 兜底：P4 就绪后移除

    def _fallback_mutate(self, data: bytes) -> bytes:
        """极简兜底变异：随机位翻转 + 小概率字典插入。"""
        rng = self._rng
        buf = bytearray(data or b"\x00")
        for _ in range(rng.randint(1, 8)):
            i = rng.randrange(len(buf))
            buf[i] ^= 1 << rng.randrange(8)
        if self.dictionary and rng.random() < 0.2:
            tok = rng.choice(self.dictionary)
            pos = rng.randrange(len(buf) + 1)
            buf[pos:pos] = tok
        return bytes(buf[: self.max_len])

    def _enqueue(self, data: bytes, result: RunResult) -> None:
        """发现新边 → 落盘并加入语料队列。"""
        sid = len(self.queue)
        path = os.path.join(self.queue_dir, f"seed_{sid:05d}")
        with open(path, "wb") as f:
            f.write(data)
        self.queue.append(Seed(id=sid, path=path, data=data,
                               found_edges=len(getattr(result, "new_edges", None)
                                               or result.edges)))
        LOG.debug("new seed: %s (%d edges)", path, len(result.edges))

    # ---------------- 崩溃处理 ----------------

    def _handle_crash(self, data: bytes, result: RunResult) -> None:
        self.total_crashes += 1
        digest = hashlib.sha1(data).hexdigest()[:8]
        path = os.path.join(self.crash_dir,
                            f"crash_{self.total_crashes:05d}_{digest}")
        if not os.path.exists(path):
            with open(path, "wb") as f:
                f.write(data)
        try:
            info = _p5_classify(result.stderr, path)
        except NotImplementedError:
            info = self._fallback_classify(result, path)  # 兜底：P5 就绪后移除
        if info.dedup_key in self._dedup:
            LOG.debug("dup crash: %s", info.dedup_key)
            return
        self._dedup.add(info.dedup_key)
        info.repro_cmd = info.repro_cmd.replace("<target>", self.target)
        # 崩溃最小化（限次限时，失败不影响主流程）
        try:
            from engine.triage import minimize_crash
            info.minimized_input = minimize_crash(
                self.target, path, vuln_type=info.vuln_type,
                timeout=1.0, max_iters=100)
        except Exception as e:
            LOG.debug("crash 最小化失败: %s", e)
        self.crashes.append(info)
        LOG.info("unique crash #%d [%s] %s",
                 len(self.crashes), info.vuln_type, path)

    def _fallback_classify(self, result: RunResult, path: str) -> CrashInfo:
        """极简兜底分类：按 stderr 首行哈希去重，类型记 unknown。"""
        key_src = (result.stderr or b"").split(b"\n", 1)[0]
        return CrashInfo(
            vuln_type="unknown",
            location="",
            dedup_key=hashlib.sha1(key_src).hexdigest()[:12],
            input_path=path,
            minimized_input=None,
            repro_cmd=f"{self.target} {path}",
            raw_stderr=result.stderr or b"",
        )

    # ---------------- 语料与统计 ----------------

    def _load_corpus(self, paths: list[str]) -> list[Seed]:
        queue: list[Seed] = []
        for p in paths:
            if not os.path.isfile(p):
                LOG.warning("corpus 项不存在，跳过: %s", p)
                continue
            with open(p, "rb") as f:
                queue.append(Seed(id=len(queue), path=p, data=f.read()))
        if not queue:
            LOG.warning("空语料，使用默认单字节种子兜底")
            queue.append(Seed(id=0, path="<default>", data=b"\x00"))
        return queue

    def _make_stats(self, start: float) -> CampaignStats:
        elapsed = max(time.time() - start, 1e-6)
        # edges_total 优先用静态分析口径（目标自身逻辑的插桩边数），
        # 无分析结果时依次回退：showmap map size → 已见边数（恒 100%，仅兜底）
        edges_total = int(self.analysis.get("edges_total") or 0)
        if edges_total <= 0:
            edges_total = int(getattr(self.coverage, "static_map_size", 0) or 0)
        if edges_total <= 0:
            edges_total = int(getattr(self.coverage, "total_edges", 0) or 0)
        # 静态分母是 *_ref 基准版的估计值；实际命中超过它说明估计偏小，
        # 以观察值为准（避免报告出现 >100% 的覆盖率）
        if len(self.unique_edges) > edges_total:
            edges_total = len(self.unique_edges)
        return CampaignStats(
            target=self.target,
            start_time=start,
            elapsed_s=elapsed,
            total_execs=self.total_execs,
            execs_per_sec=self.total_execs / elapsed,
            edges_covered=len(self.unique_edges),
            edges_total=edges_total,
            crashes=self.total_crashes,
            unique_crashes=len(self.crashes),
            timeouts=self.total_timeouts,
            corpus_size=len(self.queue),
        )
