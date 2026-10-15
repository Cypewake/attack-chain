"""Markdown 报告生成。输出目标是「能直接贴进 SRC 报告 / 护网复盘文档」。"""

from __future__ import annotations

import datetime
import os
from typing import Dict, List, Optional, Sequence

from .attck import AttckIndex, describe_node
from .model import Chain

__all__ = ["build_report", "write_report"]

ZH_DETECT = {"high": "高", "medium": "中", "low": "低"}


def _path_line(chain: Chain, path: Sequence[str]) -> str:
    return " → ".join(f"`{chain.nodes[n].name}`" for n in path) if path else "（无）"


def _path_ids_line(chain: Chain, path: Sequence[str]) -> str:
    return " → ".join(f"`{chain.nodes[n].technique}`" for n in path) if path else "（无）"


def build_report(
    chain: Chain,
    result: dict,
    index: AttckIndex,
    pictures: Optional[Dict[str, str]] = None,
    defenses: Optional[List[dict]] = None,
    problems: Optional[List[dict]] = None,
) -> str:
    """生成完整 Markdown 报告文本。"""
    pictures = pictures or {}
    defenses = defenses or []
    problems = problems or []
    L: List[str] = []

    meta = chain.meta
    best = result.get("shortest_path")

    # ---------------- 抬头 ----------------
    L.append(f"# {meta.name} —— 攻击链分析报告")
    L.append("")
    L.append("> 本报告由 attack-chain 自动生成，用于授权靶场演练与红蓝复盘。")
    L.append("")
    L.append("| 项目 | 内容 |")
    L.append("|---|---|")
    L.append(f"| 目标环境 | {meta.target or '未指定'} |")
    # 场景说明可能来自 YAML 折叠标量（>），末尾带换行会切断 Markdown 表格，先清洗
    _scenario = (meta.scenario or "未指定").strip().replace("\n", " ")
    L.append(f"| 场景说明 | {_scenario} |")
    if meta.author:
        L.append(f"| 分析者 | {meta.author} |")
    L.append(f"| 生成时间 | {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} |")
    L.append(f"| 图规模 | {result['node_count']} 个节点 / {result['edge_count']} 条边 |")
    L.append(f"| 权重口径 | `{result['weight']}` |")
    L.append(f"| ATT&CK 版本 | {index.version} |")
    L.append("")

    # ---------------- 图 ----------------
    if pictures.get("png") or pictures.get("svg"):
        L.append("## 一、攻击链图")
        L.append("")
        img = pictures.get("png") or pictures.get("svg")
        L.append(f"![攻击链图]({os.path.basename(img)})")
        L.append("")
        L.append("红线为当前最短攻击路径，节点底色对应 ATT&CK 战术阶段。")
        L.append("")

    # ---------------- 结论摘要 ----------------
    L.append("## 二、结论摘要")
    L.append("")
    if best:
        rate = result.get("shortest_path_success_rate", 0.0)
        # 5 个节点是 4 条边 —— 按边数（跳）口径，避免"5 跳"实为 5 节点的错位
        L.append(f"- **最短路径**（{len(best) - 1} 跳 / {len(best)} 个节点）：{_path_line(chain, best)}")
        L.append(f"- 对应技术链：{_path_ids_line(chain, best)}")
        L.append(f"- 该路径综合代价 `{result.get('shortest_path_cost')}`，"
                 f"整链成功概率约 **{rate:.2%}**")
    else:
        L.append("- ⚠️ **当前建模下不存在从入口到目标的完整路径** —— 请检查链路定义。")
    L.append("")

    spof = result.get("spof", [])
    if spof:
        L.append(f"- **单点故障 {len(spof)} 个**："
                 f"{'、'.join('`' + chain.nodes[n].name + '`' for n in spof)}"
                 f"（打掉任一个即整链断裂）")
    else:
        L.append("- **不存在单点故障**：攻击方已具备冗余路径，防守需多点布防。")

    cp = result.get("chokepoints", [])
    if cp:
        top = cp[0]
        L.append(f"- **最优设卡点**：`{chain.nodes[top['node']].name}`，"
                 f"覆盖 {top['coverage']:.0%} 的入口→目标路径")
    L.append("")

    gaps = result.get("detection_gaps_on_shortest", [])
    if gaps:
        L.append(f"- **最短路径上的检测盲区 {len(gaps)} 处**："
                 f"{'、'.join('`' + g['name'] + '`' for g in gaps)}"
                 f"（这些环节防守方基本看不见）")
    else:
        L.append("- 最短路径上无检测盲区。")
    L.append("")

    # ---------------- ATT&CK 映射 ----------------
    L.append("## 三、ATT&CK 技术映射")
    L.append("")
    L.append("| 节点 | 技术编号 | 技术名称 | 战术 | 检测度 | 建议数据源 |")
    L.append("|---|---|---|---|---|---|")
    for nid, node in chain.nodes.items():
        tid = index.tactic_id(node.tactic)
        zh = index.name_zh(node.tactic)
        tech = index.technique_name(node.technique, fallback="—")
        tactic_cell = f"{zh} `{tid}`" if tid else node.tactic
        tips = "；".join(node.detect_tips) if node.detect_tips else "—"
        if len(tips) > 60:
            tips = tips[:59] + "…"
        L.append(f"| {node.name} | `{node.technique}` | {tech} | {tactic_cell} | "
                 f"{ZH_DETECT.get(node.detectability, node.detectability)} | {tips} |")
    L.append("")

    # ---------------- 最短路径明细 ----------------
    L.append("## 四、最短路径明细")
    L.append("")
    if best:
        L.append("| # | 节点 | 技术编号 | 战术 | 检测度 | 单步失败率 |")
        L.append("|---|---|---|---|---|---|")
        for i, nid in enumerate(best, 1):
            n = chain.nodes[nid]
            L.append(f"| {i} | {n.name} | `{n.technique}` | {n.tactic} | "
                     f"{ZH_DETECT.get(n.detectability, n.detectability)} | {n.fail_rate:.0%} |")
        L.append("")
        L.append("> 整链成功概率是所有环节成功概率的连乘积。"
                 "单看每一步都很稳，串起来往往只剩百分之几 —— 这正是必须准备备用路径的量化理由。")
        L.append("")
    else:
        L.append("无可达路径。")
        L.append("")

    # ---------------- SPOF ----------------
    L.append("## 五、单点故障分析（SPOF）")
    L.append("")
    if spof:
        L.append("以下节点一旦被防守方阻断，**整条链断裂**：")
        L.append("")
        L.append("| 节点 | 技术编号 | 说明 |")
        L.append("|---|---|---|")
        for nid in spof:
            n = chain.nodes[nid]
            L.append(f"| {n.name} | `{n.technique}` | {n.note or '—'} |")
        L.append("")
    else:
        L.append("✅ 本链路不存在单点故障：任意单个中间节点被打掉后，攻击方仍有可达路径。")
        L.append("")

    # ---------------- 卡点排序 ----------------
    L.append("## 六、防守卡点排序")
    L.append("")
    if cp:
        L.append("按「覆盖了多少条入口→目标路径」排序，覆盖率越高越值得优先设卡：")
        L.append("")
        L.append("| 排名 | 节点 | 路径覆盖率 | 技术编号 | 平均致瘫收益 |")
        L.append("|---|---|---|---|---|")
        for i, row in enumerate(cp[:10], 1):
            n = chain.nodes[row["node"]]
            L.append(f"| {i} | {n.name} | {row['coverage']:.0%} "
                     f"({row['paths_through']}/{row['total_paths']}) | "
                     f"`{n.technique}` | impact={n.impact} |")
        L.append("")
    else:
        L.append("无可用路径，无法计算卡点。")
        L.append("")

    # ---------------- 备用路径 ----------------
    L.append("## 七、备用路径校验（两条路径原则）")
    L.append("")
    backs = result.get("backup_paths", [])
    if len(backs) >= 2:
        L.append(f"找到 **{len(backs)} 条节点不相交的路径**，独立性 {'✅ 通过' if result.get('backup_disjoint') else '❌ 未通过'}：")
        L.append("")
        for i, p in enumerate(backs, 1):
            L.append(f"- 路径 {i}：{_path_line(chain, p)}")
        L.append("")
        conflicts = result.get("backup_conflicts", [])
        if conflicts:
            L.append("⚠️ 发现路径共用节点：")
            L.append("")
            for c in conflicts:
                shared = "、".join(f"`{chain.nodes[n].name}`" for n in c["shared_nodes"])
                L.append(f"- {c['advice']}（共用：{shared}）")
            L.append("")
    elif len(backs) == 1:
        L.append("⚠️ **只存在一条可行路径**，备用路径校验未通过。"
                 "这意味着防守方只需在该路径任意一点设卡即可全盘阻断 —— "
                 "红队必须再准备一条不共用中间节点的路。")
        L.append("")
        L.append(f"- 唯一路径：{_path_line(chain, backs[0])}")
        L.append("")
    else:
        L.append("无可达路径。")
        L.append("")

    # ---------------- 检测盲区 ----------------
    L.append("## 八、检测覆盖面分析")
    L.append("")
    all_gaps = result.get("detection_gaps_all", [])
    if all_gaps:
        L.append(f"全链路共 **{len(all_gaps)} 个节点**处于防守盲区（detectability=low）：")
        L.append("")
        L.append("| 节点 | 技术编号 | 风险 | 建议 |")
        L.append("|---|---|---|---|")
        for g in all_gaps:
            L.append(f"| {g['name']} | `{g['technique']}` | {g['risk']} | {g['suggestion']} |")
        L.append("")
    else:
        L.append("全链路无低可见度节点。")
        L.append("")

    if gaps:
        L.append("**最短路径上的盲区**（防守方最该着急的部分）：")
        L.append("")
        for g in gaps:
            L.append(f"- `{g['name']}`（`{g['technique']}`）—— {g['suggestion']}")
        L.append("")

    # ---------------- 防守模拟 ----------------
    if defenses:
        L.append("## 九、防守阻断模拟")
        L.append("")
        L.append("下表回答的是实战问题：**如果我在某点设卡，链路会怎么样？**")
        L.append("")
        L.append("| 设卡点 | 封锁后是否可达 | 剩余独立路径 | 结论 |")
        L.append("|---|---|---|---|")
        for d in defenses:
            names = "、".join(f"`{chain.nodes[n].name}`" for n in d["blocked"])
            L.append(f"| {names} | {'是' if d['still_reachable'] else '否'} | "
                     f"{d['independent_path_count']} 条 | {d['impact']} |")
        L.append("")

    # ---------------- 一致性检查 ----------------
    if problems:
        L.append("## 十、模型一致性检查")
        L.append("")
        L.append("| 节点 | 级别 | 问题 |")
        L.append("|---|---|---|")
        for p in problems:
            L.append(f"| `{p['node']}` | {p['level']} | {p['message']} |")
        L.append("")

    # ---------------- 尾注 ----------------
    L.append("---")
    L.append("")
    L.append("**合规说明**：本报告仅记录授权靶场与演练环境下的攻击路径推演，"
             "不包含任何针对真实系统的利用代码。")
    L.append("")
    return "\n".join(L)


def write_report(text: str, out_path: str) -> str:
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fp:
        fp.write(text)
    return out_path
