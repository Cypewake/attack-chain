"""核心图算法：最短路径、单点故障、卡点排序、备用路径、检测覆盖。

设计原则（来自开发文档第三章）：
    analyze.py 只依赖 networkx —— 所有算法集中在这里，面试时讲这一个文件就够。
所有函数都是「纯函数」：输入 Chain+参数，输出可序列化的 dict，不做打印、不写文件。
"""

from __future__ import annotations

import itertools
import math
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

import networkx as nx

from .model import DETECT_COST, Chain, ChainNode

__all__ = [
    "build_graph",
    "shortest_path",
    "find_spof",
    "chokepoint_ranking",
    "backup_paths",
    "detection_gaps",
    "path_success_rate",
    "simulate_defense",
    "analyze",
]

SUPER_SRC = "__ENTRY__"
SUPER_SINK = "__OBJECTIVE__"


# ---------------------------------------------------------------- 构图与代价模型


def node_cost(node: ChainNode, weight: str = "balanced") -> float:
    """单个节点的通行代价。三种权重模式对应三种视角。

    balanced（默认，攻方视角）: 代价 = 暴露成本 × 失败惩罚 ÷ 收益折让
        - 检测越强的节点越贵（暴露风险高）
        - 失败率越高越贵
        - impact 越大越便宜（打下来收益高，值得优先走）
        这是「ROI 最短路径」——不是最少跳数，而是综合代价最低的那条。
    stealth（隐蔽视角）: 只按暴露成本算，纯粹挑防守看不见的路走。
    impact（文档原始模式）: 直接用 impact 作为权重，语义是「收益最大化路径」。
    hops: 不计权重，纯跳数最短。

    返回值恒为正 —— Dijkstra 不接受负权边。
    """
    detect = DETECT_COST.get(node.detectability, 1.0)

    if weight == "hops":
        return 1.0
    if weight == "stealth":
        return detect
    if weight == "impact":
        return float(max(node.impact, 1))

    # balanced
    fail_penalty = 1.0 + float(node.fail_rate)
    value_discount = 1.0 / (1.0 + 0.1 * float(node.impact))
    return round(detect * fail_penalty * value_discount, 4)


def build_graph(chain: Chain, weight: str = "balanced") -> nx.DiGraph:
    """把 Chain 转成带权有向图。

    边权 = 目标节点代价 + 跃迁失败惩罚。
    这样「路径总代价」天然等于沿途节点代价之和加上所有跃迁的失败惩罚。
    """
    g = nx.DiGraph()
    for nid, node in chain.nodes.items():
        g.add_node(nid, **{
            "name": node.name,
            "tactic": node.tactic,
            "technique": node.technique,
            "kind": node.kind,
            "detectability": node.detectability,
            "impact": node.impact,
            "fail_rate": node.fail_rate,
            "asset": node.asset,
            "cost": node_cost(node, weight),
        })
    for edge in chain.edges:
        g.add_edge(edge.src, edge.dst, **{
            "condition": edge.condition,
            "fail_rate": edge.fail_rate,
            "penalty": round(1.0 + float(edge.fail_rate), 4),
            "weight": round(
                node_cost(chain.nodes[edge.dst], weight) + 1.0 + float(edge.fail_rate), 4
            ),
        })
    return g


def _with_super_nodes(g: nx.DiGraph, entries: Sequence[str], objectives: Sequence[str]) -> nx.DiGraph:
    """加超级源/超级汇。

    用超级源一次跑完整图，而不是对每个入口循环跑 N 次 shortest_path ——
    复杂度从 O(V·(E+V)logV) 降到一次 Dijkstra，这是这个工具的面试加分点。
    """
    out = g.copy()
    out.add_node(SUPER_SRC, name="攻击入口", cost=0.0)
    out.add_node(SUPER_SINK, name="目标旗帜", cost=0.0)
    for e in entries:
        if e not in out:
            continue          # 入口被防守方封禁后已不在图中，跳过即可
        out.add_edge(SUPER_SRC, e, weight=max(g.nodes[e].get("cost", 1.0), 0.01))
    for o in objectives:
        if o not in out:
            continue          # 目标被封禁后跳过；若全部入口/目标都不在，则无路可走（即已切断）
        out.add_edge(o, SUPER_SINK, weight=0.0)
    return out


# ---------------------------------------------------------------- 算法 1：最短路径


def shortest_path(
    g: nx.DiGraph, entries: Sequence[str], objectives: Sequence[str]
) -> Optional[List[str]]:
    """多源到多目标的最短路径。不可达返回 None。"""
    sg = _with_super_nodes(g, entries, objectives)
    try:
        path = nx.shortest_path(sg, SUPER_SRC, SUPER_SINK, weight="weight")
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return None
    inner = [n for n in path if n not in (SUPER_SRC, SUPER_SINK)]
    return inner


# ---------------------------------------------------------------- 算法 2：单点故障


def find_spof(g: nx.DiGraph, entries: Sequence[str], objectives: Sequence[str]) -> List[str]:
    """单点故障：删掉该节点后，入口到目标不再连通。

    性能优化：先对**无向副本**求割点（articulation points）。非割点不可能是单点故障，
    只对割点做精确验证。复杂度从 O(V·(V+E)) 降到 O(V+E) 的预筛 + O(C·(V+E)) 的验证，
    其中 C 是割点数量，通常远小于 V。
    """
    entry_set, obj_set = set(entries), set(objectives)
    undirected = nx.Graph(g.to_undirected())
    candidates = set(nx.articulation_points(undirected))

    spof: List[str] = []
    for node in g.nodes():
        if node in entry_set or node in obj_set:
            continue          # 入口和目标本身不是「单点故障」，它们是链路的两端
        if node not in candidates:
            continue          # 非割点：删掉它图仍连通，直接跳过

        probe = g.copy()
        probe.remove_node(node)
        if not any(nx.has_path(probe, e, o) for e, o in itertools.product(entries, objectives)):
            spof.append(node)
    return sorted(spof)


# ---------------------------------------------------------------- 算法 3：卡点排序


def chokepoint_ranking(
    g: nx.DiGraph,
    entries: Sequence[str],
    objectives: Sequence[str],
    max_paths: int = 2000,
    cutoff: Optional[int] = 14,
) -> List[dict]:
    """按「有多少条 entry→objective 路径经过该节点」排序，给出防守优先级。

    与 SPOF 的区别：SPOF 是二元的（断/不断），chokpoint 是连续的（覆盖率 0~1）。
    实战里真正有用的是后者 —— 一个覆盖 78% 路径的节点，比一个覆盖 100% 但
    根本没被用到的节点更值得设卡。

    注意：这是纯统计口径，不看节点代价。要「低代价高覆盖」的卡点看
    simulate_defense 的返回结果。
    """
    paths: List[List[str]] = []
    for e, o in itertools.product(entries, objectives):
        if not nx.has_path(g, e, o):
            continue
        for p in nx.all_simple_paths(g, e, o, cutoff=cutoff):
            paths.append(p)
            if len(paths) >= max_paths:
                break
        if len(paths) >= max_paths:
            break

    if not paths:
        return []

    total = len(paths)
    counter: Dict[str, int] = {}
    for p in paths:
        for nid in set(p):
            counter[nid] = counter.get(nid, 0) + 1

    entry_set, obj_set = set(entries), set(objectives)
    ranked: List[dict] = []
    for nid, count in counter.items():
        if nid in entry_set or nid in obj_set:
            continue
        ranked.append({
            "node": nid,
            "coverage": round(count / total, 4),
            "paths_through": count,
            "total_paths": total,
        })
    ranked.sort(key=lambda r: (-r["coverage"], r["node"]))
    return ranked


# ---------------------------------------------------------------- 算法 4：备用路径


def backup_paths(
    g: nx.DiGraph, entries: Sequence[str], objectives: Sequence[str], wanted: int = 2
) -> List[List[str]]:
    """贪心求取「节点不相交」的备用路径。

    做法：找到一条最短路后，把这条路的**中间节点**从候选集里抹掉再找下一条。
    这样得到的任意两条路径，中间节点集合交集为空 —— 正好对应红队的「两条路径原则」：
    防守方封掉一条路上的任意一点，另一条仍能走通。

    为什么不用 nx.node_disjoint_paths 的最大流版？
    因为它给出的是「理论最大条数」，会把很多代价极高的绕远路也算成一条。
    实战中备用路径的价值取决于它走不走得通、代价高不高，所以这里用「贪心 + 代价递增」，
    得到的前 N 条最便宜的不相交路径才是真能用的备选。
    """
    found: List[List[str]] = []
    banned: set = set()
    working = g

    for _ in range(wanted):
        # 把上一次路径的中间节点删掉后再搜：保证与已有路径节点不相交
        probe = working.copy()
        probe.remove_nodes_from([n for n in banned if n in probe])
        path = shortest_path(probe, entries, objectives)
        if not path:
            break
        found.append(path)
        banned.update(n for n in path[1:-1])   # 端点（入口/目标）允许共用
    return found


def paths_are_disjoint(paths: Sequence[Sequence[str]], strict: bool = True) -> Tuple[bool, List[dict]]:
    """校验路径两两之间是否真的独立。strict=True 时连首尾节点也不许共用。"""
    conflicts: List[dict] = []
    ok = True
    for i, p1 in enumerate(paths):
        for j, p2 in enumerate(paths[i + 1:], start=i + 1):
            a = set(p1) if strict else set(p1[1:-1])
            b = set(p2) if strict else set(p2[1:-1])
            overlap = a & b
            if overlap:
                ok = False
                conflicts.append({
                    "path_a": i,
                    "path_b": j,
                    "shared_nodes": sorted(overlap),
                    "advice": f"路径 {i + 1} 与 {j + 1} 共用节点 {sorted(overlap)}，"
                              f"防守方只需封一处即可同时切断两条链",
                })
    return ok, conflicts


# ---------------------------------------------------------------- 算法 5：检测视角


def detection_gaps(g: nx.DiGraph, on_path: Optional[Sequence[str]] = None) -> List[dict]:
    """检测盲区：detectability 为 low 的节点。

    on_path 给定时只看该路径上的节点 —— 这才是防守方真正要问的问题：
    「这条具体路径上，我哪里是瞎的？」
    """
    scope = list(on_path) if on_path is not None else list(g.nodes())
    gaps: List[dict] = []
    for nid in scope:
        if nid not in g.nodes:
            continue
        data = g.nodes[nid]
        if data.get("detectability") == "low":
            gaps.append({
                "node": nid,
                "name": data.get("name", nid),
                "technique": data.get("technique", ""),
                "risk": "防守方在此环节缺少有效数据源",
                "suggestion": "补充数据源，或接受该环节不可见并在上游/下游设卡",
            })
    return gaps


def path_success_rate(chain: Chain, path: Sequence[str]) -> float:
    """一条路径的整体成功概率 = ∏(1 - 节点失败率) × ∏(1 - 边失败率)。

    这是把「链」当链看的直接后果：单步成功率看着都不低，
    串起来可能只剩下百分之几 —— 这条数值能直接支撑红队「要不要多准备一条路」的判断。
    """
    if len(path) < 2:
        return 0.0
    rate = 1.0
    for nid in path:
        node = chain.nodes[nid]
        rate *= (1.0 - node.fail_rate)
    for u, v in zip(path, path[1:]):
        edge = g_edge(chain, u, v)
        if edge is not None:
            rate *= (1.0 - edge.fail_rate)
    return round(rate, 6)


def g_edge(chain: Chain, u: str, v: str):
    """取 u->v 那条边（同一对节点只会定义一次，取不到返回 None）。"""
    for e in chain.edges:
        if e.src == u and e.dst == v:
            return e
    return None


# ---------------------------------------------------------------- 防守模拟


def simulate_defense(
    chain: Chain,
    blocked: Sequence[str],
    weight: str = "balanced",
) -> dict:
    """模拟「防守方封掉某些节点之后」的链路状态。

    这是 README 杀手锏演示的底层实现：封掉 T1190 → 输出「已无完整路径」；
    补一条旁路 → 输出「两条独立路径」。
    """
    g0 = build_graph(chain, weight)
    base = shortest_path(g0, chain.entries, chain.objective_ids)

    g1 = g0.copy()
    g1.remove_nodes_from([n for n in blocked if n in g1])
    after = shortest_path(g1, chain.entries, chain.objective_ids)

    still_reachable = after is not None
    alternatives = backup_paths(g1, chain.entries, chain.objective_ids, wanted=3) if still_reachable else []

    if still_reachable:
        impact_desc = f"仍有完整路径（最短 {len(after or [])} 跳）"
    elif base is None:
        impact_desc = "封禁前本就不可达（链路定义有问题）"
    else:
        impact_desc = "已无完整路径 —— 攻击链被彻底切断"

    return {
        "blocked": list(blocked),
        "before_path": base,
        "after_path": after,
        "still_reachable": still_reachable,
        "alternative_paths": alternatives,
        "independent_path_count": len(alternatives),
        "impact": impact_desc,
    }


# ---------------------------------------------------------------- 汇总


def analyze(chain: Chain, weight: str = "balanced") -> dict:
    """跑完全部分析，返回可直接喂给报告生成器的 dict。"""
    g = build_graph(chain, weight)
    entries, objectives = chain.entries, chain.objective_ids

    best = shortest_path(g, entries, objectives)
    ok, conflicts = paths_are_disjoint(backup_paths(g, entries, objectives, wanted=2), strict=False)

    result: Dict[str, object] = {
        "weight": weight,
        "node_count": g.number_of_nodes(),
        "edge_count": chain_edges_count(chain),
        "entries": entries,
        "objectives": objectives,
        "shortest_path": best,
        "shortest_path_cost": (
            round(sum(
                g.nodes[n].get("cost", 0.0) for n in (best or [])
            ), 3) if best else None
        ),
        "shortest_path_success_rate": path_success_rate(chain, best) if best else 0.0,
        "spof": find_spof(g, entries, objectives),
        "chokepoints": chokepoint_ranking(g, entries, objectives),
        "backup_paths": backup_paths(g, entries, objectives, wanted=3),
        "backup_disjoint": ok,
        "backup_conflicts": conflicts,
        "detection_gaps_all": detection_gaps(g),
        "detection_gaps_on_shortest": detection_gaps(g, best) if best else [],
    }
    return result


def chain_edges_count(chain: Chain) -> int:
    return len(chain.edges)
