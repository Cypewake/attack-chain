"""attack-chain 单元测试。

运行方式（二选一）：
    python -m pytest tests/ -v          # 推荐，需要 pip install pytest
    python tests/test_attackchain.py    # 无 pytest 时的兜底直跑

覆盖面：
    model      字段校验（枚举/越界/自环）
    loader     YAML 加载 + 简写目标 + 悬空引用报错
    analyze    node_cost 四种权重、最短路径、SPOF、卡点排序、
               备用路径不相交、成功率乘法、防守模拟
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attackchain.analyze import (          # noqa: E402
    backup_paths,
    build_graph,
    chokepoint_ranking,
    find_spof,
    node_cost,
    path_success_rate,
    paths_are_disjoint,
    shortest_path,
    simulate_defense,
)
from attackchain.loader import ChainError, load_chain_file  # noqa: E402
from attackchain.model import (          # noqa: E402
    Chain,
    ChainEdge,
    ChainNode,
    Meta,
    Objective,
)


# ---------------------------------------------------------------- 测试用小链路
#
#     e0 ──> a1 ──> b2 ──> obj3        （主线）
#      │            ↑
#      └──> c4 ─────┘                 （旁路，共享 b2）
#
# b2 是割点（删掉后 obj3 不可达），a1/c4 不是。


def make_chain() -> Chain:
    nodes = {
        "e0": ChainNode(id="e0", name="入口", tactic="Initial Access",
                        technique="T1190", kind="entry", fail_rate=0.1),
        "a1": ChainNode(id="a1", name="立足点A", tactic="Execution",
                        technique="T1059", fail_rate=0.2),
        "b2": ChainNode(id="b2", name="卡点B", tactic="Lateral Movement",
                        technique="T1021", detectability="low", fail_rate=0.2),
        "c4": ChainNode(id="c4", name="旁路C", tactic="Discovery",
                        technique="T1018", fail_rate=0.2),
        "obj3": ChainNode(id="obj3", name="目标", tactic="Privilege Escalation",
                          technique="T1068", kind="objective", impact=10,
                          fail_rate=0.05),
    }
    edges = [
        ChainEdge(src="e0", dst="a1", fail_rate=0.1),
        ChainEdge(src="a1", dst="b2", fail_rate=0.1),
        ChainEdge(src="e0", dst="c4", fail_rate=0.1),
        ChainEdge(src="c4", dst="b2", fail_rate=0.1),
        ChainEdge(src="b2", dst="obj3", fail_rate=0.1),
    ]
    return Chain(
        meta=Meta(name="测试链"),
        nodes=nodes,
        edges=edges,
        objectives={"obj3": Objective(id="obj3", name="目标")},
    )


def make_disjoint_chain() -> Chain:
    """两条真正节点不相交的路线（备用路径测试专用）：

        e0 ──> a1 ──> b2 ──> obj3     （主线）
         └──> c4 ──> d5 ─────────     （旁路，与主线不共享任何中间节点）
    """

    def n(nid, tactic, technique):
        return ChainNode(id=nid, name=nid, tactic=tactic, technique=technique,
                         fail_rate=0.1)

    nodes = {
        "e0": ChainNode(id="e0", name="入口", tactic="Initial Access",
                        technique="T1190", kind="entry", fail_rate=0.1),
        "a1": n("a1", "Execution", "T1059"),
        "b2": n("b2", "Lateral Movement", "T1021"),
        "c4": n("c4", "Discovery", "T1018"),
        "d5": n("d5", "Lateral Movement", "T1021"),
        "obj3": ChainNode(id="obj3", name="目标", tactic="Privilege Escalation",
                          technique="T1068", kind="objective", impact=10,
                          fail_rate=0.05),
    }
    edges = [
        ChainEdge(src="e0", dst="a1", fail_rate=0.1),
        ChainEdge(src="a1", dst="b2", fail_rate=0.1),
        ChainEdge(src="b2", dst="obj3", fail_rate=0.1),
        ChainEdge(src="e0", dst="c4", fail_rate=0.1),
        ChainEdge(src="c4", dst="d5", fail_rate=0.1),
        ChainEdge(src="d5", dst="obj3", fail_rate=0.1),
    ]
    return Chain(meta=Meta(name="双路测试链"), nodes=nodes, edges=edges,
                 objectives={"obj3": Objective(id="obj3", name="目标")})


# ---------------------------------------------------------------- model


class TestModel:
    def test_fail_rate_越界报错(self):
        with pytest.raises(ChainError):
            ChainNode(id="x", name="x", tactic="t", technique="T0",
                      fail_rate=1.0)          # 必须 [0, 1)

    def test_kind_非法报错(self):
        with pytest.raises(ChainError):
            ChainNode(id="x", name="x", tactic="t", technique="T0",
                      kind="hacker")

    def test_detectability_非法报错(self):
        with pytest.raises(ChainError):
            ChainNode(id="x", name="x", tactic="t", technique="T0",
                      detectability="hidden")

    def test_自环requires报错(self):
        with pytest.raises(ChainError):
            ChainNode(id="x", name="x", tactic="t", technique="T0",
                      requires=["x"])

    def test_边自环报错(self):
        with pytest.raises(ChainError):
            ChainEdge(src="x", dst="x").validate()

    def test_没有入口报错(self):
        chain = make_chain()
        chain.nodes["e0"].kind = "foothold"
        with pytest.raises(ChainError):
            chain.validate_graph()

    def test_悬空引用报错(self):
        chain = make_chain()
        chain.edges.append(ChainEdge(src="ghost", dst="a1"))
        with pytest.raises(ChainError):
            chain.validate_graph()


# ---------------------------------------------------------------- analyze


class TestNodeCost:
    def test_四口径全为正(self):
        chain = make_chain()
        node = chain.nodes["b2"]
        for w in ("balanced", "stealth", "impact", "hops"):
            assert node_cost(node, w) > 0

    def test_stealth_检测越强越贵(self):
        hi = ChainNode(id="hi", name="高暴露", tactic="t", technique="T0",
                       detectability="high")
        lo = ChainNode(id="lo", name="低暴露", tactic="t", technique="T0",
                       detectability="low")
        assert node_cost(hi, "stealth") > node_cost(lo, "stealth")

    def test_hops_恒为1(self):
        chain = make_chain()
        for node in chain.nodes.values():
            assert node_cost(node, "hops") == 1.0


class TestShortestPath:
    def test_最短路走边数最少的方向(self):
        chain = make_chain()
        g = build_graph(chain, "hops")
        path = shortest_path(g, chain.entries, chain.objective_ids)
        assert path is not None
        assert path[0] == "e0" and path[-1] == "obj3"

    def test_全部封锁后不可达(self):
        chain = make_chain()
        g = build_graph(chain, "hops")
        g.remove_node("b2")
        assert shortest_path(g, chain.entries, chain.objective_ids) is None


class TestSpof:
    def test_共享节点是单点故障(self):
        chain = make_chain()
        g = build_graph(chain)
        assert find_spof(g, chain.entries, chain.objective_ids) == ["b2"]


class TestChokepoint:
    def test_共享节点覆盖率最高(self):
        chain = make_chain()
        g = build_graph(chain)
        ranked = chokepoint_ranking(g, chain.entries, chain.objective_ids)
        assert ranked, "至少应给出一个卡点"
        assert ranked[0]["node"] == "b2"
        assert ranked[0]["coverage"] == 1.0    # 所有路径都经过 b2
        # 端点（入口/目标）不应出现在卡点表里
        assert all(r["node"] not in ("e0", "obj3") for r in ranked)


class TestBackupPaths:
    def test_双路链求出两条不相交路径(self):
        chain = make_disjoint_chain()
        g = build_graph(chain)
        paths = backup_paths(g, chain.entries, chain.objective_ids, wanted=2)
        assert len(paths) == 2
        ok, conflicts = paths_are_disjoint(paths, strict=False)
        assert ok and not conflicts

    def test_共享单点的链只有一条不相交路径(self):
        chain = make_chain()
        g = build_graph(chain)
        paths = backup_paths(g, chain.entries, chain.objective_ids, wanted=2)
        assert len(paths) == 1            # 旁路 c4 也要经过 b2，无法绕开

    def test_彻底切断后无备用路径(self):
        chain = make_chain()
        g = build_graph(chain)
        g.remove_node("b2")
        assert backup_paths(g, chain.entries, chain.objective_ids, wanted=2) == []


class TestSuccessRate:
    def test_乘法衰减低于任一单步(self):
        chain = make_chain()
        rate = path_success_rate(chain, ["e0", "a1", "b2", "obj3"])
        assert 0 < rate < 1
        single = (1 - 0.1) * (1 - 0.2)          # 最强的两步单独成功率
        assert rate < single

    def test_单节点路径按0处理(self):
        chain = make_chain()
        assert path_success_rate(chain, ["e0"]) == 0.0


class TestSimulateDefense:
    def test_封锁割点彻底切断(self):
        chain = make_chain()
        r = simulate_defense(chain, ["b2"])
        assert not r["still_reachable"]
        assert r["alternative_paths"] == []

    def test_封锁非关键点仍有路径(self):
        chain = make_chain()
        r = simulate_defense(chain, ["a1"])
        assert r["still_reachable"]
        assert r["after_path"] == ["e0", "c4", "b2", "obj3"]

    def test_封锁入口后不可达(self):
        chain = make_chain()
        r = simulate_defense(chain, ["e0"])
        assert not r["still_reachable"]


# ---------------------------------------------------------------- loader（含示例文件回归）


EXAMPLE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "examples", "vulnstack8-chain.yaml",
)


class TestLoader:
    def test_加载示例攻击链(self):
        chain = load_chain_file(EXAMPLE)
        chain.validate_graph()
        assert "web-rce" in chain.nodes
        assert chain.objective_ids == ["domain-admin"]

    def test_示例全链路分析不崩(self):
        chain = load_chain_file(EXAMPLE)
        result = simulate_defense(chain, ["web-rce"])
        # 封掉外网 RCE 后路线 B（RDP 爆破）仍在，链不该断
        assert result["still_reachable"]

    def test_文件不存在报错(self):
        with pytest.raises(ChainError):
            load_chain_file("不存在的文件.yaml")


# ---------------------------------------------------------------- 无 pytest 兜底

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
