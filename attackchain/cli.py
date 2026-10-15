"""命令行入口。

用法：
    python -m attackchain --input chain.yaml --out report/
    python -m attackchain --input chain.yaml --out report/ --block file-upload
    python -m attackchain --input chain.yaml --json result.json --no-render
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional, Sequence

from .analyze import analyze, simulate_defense
from .attck import describe_node, load_default_index
from .loader import ChainError, load_chain_file
from .render import render
from .report import build_report, write_report

DEFAULT_FORMATS = "svg,png,dot,mmd"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="attackchain",
        description="攻击链路径分析：图 + 最短路径 + 单点故障 + 备用路径 + 检测盲区",
    )
    p.add_argument("--input", "-i", required=True, help="攻击链 YAML 文件")
    p.add_argument("--out", "-o", default="report", help="输出目录（默认 report/）")
    p.add_argument(
        "--format", "-f", default=DEFAULT_FORMATS,
        help=f"渲染格式，逗号分隔（默认 {DEFAULT_FORMATS}）。支持 svg/png/dot/mmd/pdf/gv-png",
    )
    p.add_argument(
        "--weight", "-w", default="balanced",
        choices=["balanced", "stealth", "impact", "hops"],
        help="路径权重口径：balanced=攻方ROI / stealth=最隐蔽 / impact=收益最大 / hops=最少跳数",
    )
    p.add_argument("--highlight", nargs="*", default=None,
                   help="高亮节点 id；不给则自动高亮最短路径")
    p.add_argument("--block", nargs="*", default=None,
                   help="模拟防守方封禁的节点 id 列表，输出封锁后的链路状态")
    p.add_argument("--attck-data", default=None, help="自定义 ATT&CK 战术表 JSON 路径")
    p.add_argument("--json", dest="json_out", default=None, help="把分析结果导出为 JSON")
    p.add_argument("--no-render", action="store_true", help="跳过图片渲染")
    p.add_argument("--no-report", action="store_true", help="跳过 Markdown 报告")
    p.add_argument("--quiet", "-q", action="store_true", help="少输出")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    # ---- 加载 ----
    try:
        chain = load_chain_file(args.input)
    except ChainError as exc:
        print(f"[错误] 加载失败：{exc}", file=sys.stderr)
        return 2

    index = load_default_index(args.attck_data)
    problems = index.check(chain)
    chain, filled = index.enrich(chain)

    # ---- 分析 ----
    result = analyze(chain, args.weight)

    hl = args.highlight if args.highlight is not None else (result.get("shortest_path") or [])

    # ---- 渲染 ----
    pictures: dict = {}
    if not args.no_render:
        formats = [f.strip() for f in args.format.split(",") if f.strip()]
        tactic_order = {t: index.order(t) for t in {n.tactic for n in chain.nodes.values()}}
        tactic_color = {t: index.color(t) for t in {n.tactic for n in chain.nodes.values()}}
        pictures = render(chain, tactic_order, tactic_color, hl, args.out, formats)

    # ---- 防守模拟 ----
    defenses: List[dict] = []
    if args.block:
        defenses.append(simulate_defense(chain, args.block, args.weight))
    else:
        # 默认对前 3 个卡点各做一次封锁模拟，这才是报告里最有价值的部分
        for row in (result.get("chokepoints") or [])[:3]:
            defenses.append(simulate_defense(chain, [row["node"]], args.weight))

    # ---- 报告 ----
    report_path = ""
    if not args.no_report:
        md = build_report(chain, result, index, pictures, defenses, problems)
        report_path = write_report(md, os.path.join(args.out, "report.md"))

    # ---- JSON ----
    if args.json_out:
        payload = {
            k: v for k, v in result.items()
        }
        payload["meta"] = {
            "name": chain.meta.name,
            "target": chain.meta.target,
            "scenario": chain.meta.scenario,
        }
        payload["defenses"] = defenses
        payload["problems"] = problems
        os.makedirs(os.path.dirname(args.json_out) or ".", exist_ok=True)
        with open(args.json_out, "w", encoding="utf-8") as fp:
            json.dump(payload, fp, ensure_ascii=False, indent=2)

    # ---- 控制台摘要 ----
    if not args.quiet:
        _print_summary(chain, result, pictures, report_path, defenses, index)

    return 0


def _print_summary(chain, result, pictures, report_path, defenses, index) -> None:
    best = result.get("shortest_path")
    print(f"\n攻击链：{chain.meta.name}  "
          f"({result['node_count']} 节点 / {result['edge_count']} 边)")
    print("-" * 68)

    if best:
        print("最短路径：")
        for i, nid in enumerate(best, 1):
            n = chain.nodes[nid]
            print(f"  {i}. {n.name:<16} [{n.technique}]  "
                  f"检测:{n.detectability:<6} 失败率:{n.fail_rate:.0%}")
        print(f"  → 综合代价 {result['shortest_path_cost']}，"
              f"整链成功率 {result['shortest_path_success_rate']:.2%}")
    else:
        print("最短路径：无（当前建模下入口不可达目标）")

    spof = result.get("spof", [])
    print(f"\n单点故障({len(spof)})："
          + ("、".join(chain.nodes[n].name for n in spof) if spof else "无"))

    cp = result.get("chokepoints", [])
    if cp:
        top = cp[0]
        print(f"最优设卡点：{chain.nodes[top['node']].name} "
              f"(覆盖 {top['coverage']:.0%} 路径)")

    backs = result.get("backup_paths", [])
    print(f"可用独立路径：{len(backs)} 条"
          f"（两两节点不相交：{'是' if result.get('backup_disjoint') else '否'}）")

    gaps = result.get("detection_gaps_all", [])
    print(f"检测盲区：{len(gaps)} 个 "
          + ("、".join(g["name"] for g in gaps) if gaps else ""))

    if defenses:
        print("\n防守模拟：")
        for d in defenses:
            names = "、".join(chain.nodes[n].name for n in d["blocked"])
            flag = "仍可达" if d["still_reachable"] else "已切断"
            print(f"  封锁 {names:<20} → {flag}（{d['impact']}）")

    if pictures:
        print("\n输出文件：")
        for fmt, path in pictures.items():
            print(f"  [{fmt}] {path}")
    if report_path:
        print(f"  [报告] {report_path}")
    print()


if __name__ == "__main__":
    raise SystemExit(main())
