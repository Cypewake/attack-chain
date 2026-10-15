"""渲染：自研布局 + SVG / PNG / Mermaid 输出。

★ 与原始开发文档的关键差异（实测环境倒逼出来的改进）：
  原设计依赖 Graphviz 的 `dot` 可执行文件。本机实测 **没有安装 Graphviz**（Windows 环境常见），
  一旦依赖它，工具在最常见的场景下直接不可用。因此这里改成：
    - **内置纯 Python 分层布局器**（按 ATT&CK 战术阶段分层），SVG 直接手写输出 —— 零外部依赖
    - PNG 用 Pillow 画，同样零依赖
    - Mermaid 直接出文本，可贴 GitHub Issue
    - DOT 文本仍然导出，但**只在系统装了 dot 时才调用它**，属于可选增强而非必需

  这个改动带来的收益是：工具可以在任何装了 Python 的机器上跑，
  包括没有管理员权限、没法装 Graphviz 的环境 —— 这是「能实际应用」的前提。
"""

from __future__ import annotations

import html
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from .model import Chain

__all__ = ["layout", "render_svg", "render_png", "render_dot", "render_mermaid", "render"]

#: 未知战术的兜底色
DEFAULT_COLOR = "#DDE3EA"


@dataclass
class Box:
    """布局后的一个节点盒子。"""

    id: str
    x: float          # 左上角 x
    y: float          # 左上角 y
    w: float
    h: float
    fill: str
    label_lines: List[str]
    on_path: bool


# ---------------------------------------------------------------- 文本度量


def _char_width(ch: str, font_size: int) -> float:
    """按字符类型估算宽度。CJK 近似占一个字号宽，ASCII 约占 0.55。"""
    if ord(ch) > 0x2E80:      # CJK / 全角标点
        return font_size
    if ch in "iljt.,'|!":
        return font_size * 0.30
    if ch.isupper():
        return font_size * 0.66
    return font_size * 0.55


def _text_width(text: str, font_size: int) -> float:
    return sum(_char_width(c, font_size) for c in text)


FONT_SIZE = 14
LINE_HEIGHT = 19
PAD_X = 14
PAD_Y = 11
RANK_GAP = 105           # 层与层的垂直间距
NODE_GAP = 38            # 同层节点水平间距
MARGIN = 40


# ---------------------------------------------------------------- 布局


def layout(chain: Chain, tactic_order: Dict[str, int], tactic_color: Dict[str, str],
           highlight: Optional[Sequence[str]] = None) -> Tuple[List[Box], float, float]:
    """分层布局：按 ATT&CK 战术阶段分层，层内按定义顺序排列。

    为什么用分层而不是力导向布局？
    攻击链天然有方向性 —— 从「初始访问」到「目标达成」是一条自上而下的时间线。
    力导向布局会把这条语义丢掉；分层布局则直观表达「进展到了哪个阶段」，
    看图的人不需要读节点内容就能判断攻击进行到哪一步。
    """
    hl = set(highlight or [])

    # 1) 为每个节点算一个 rank（战术阶段序号，兜底 99）
    ranks: Dict[str, int] = {}
    for nid, node in chain.nodes.items():
        ranks[nid] = tactic_order.get(node.tactic, 99)

    # 2) 把未知战术的节点按拓扑顺序压到已知层之间：至少保证前后依赖关系不倒挂
    max_known = max([r for r in ranks.values() if r != 99], default=0)
    try:
        topo = list(_topological(chain))
        for idx, nid in enumerate(topo):
            if ranks[nid] == 99:
                ranks[nid] = max_known + 1 + (idx % 3)   # 允许重层，但保持整体向下
    except Exception:        # 图有环时退化为按定义顺序
        for i, nid in enumerate(chain.nodes):
            if ranks[nid] == 99:
                ranks[nid] = max_known + 1 + (i % 3)

    # 3) 分层 → 同层按定义顺序排
    by_rank: Dict[int, List[str]] = {}
    for nid in chain.nodes:
        by_rank.setdefault(ranks[nid], []).append(nid)

    boxes: List[Box] = []
    ordered_ranks = sorted(by_rank.keys())

    for rank in ordered_ranks:
        members = by_rank[rank]
        widths: List[float] = []
        heights: List[float] = []
        labels: Dict[str, List[str]] = {}

        for nid in members:
            node = chain.nodes[nid]
            lines = [
                node.name,
                f"[{node.technique}] 检测:{ {'high':'高','medium':'中','low':'低'}.get(node.detectability, node.detectability) }",
            ]
            if node.asset:
                lines.append(f"@{node.asset}")
            labels[nid] = lines
            widths.append(max(_text_width(line, FONT_SIZE) for line in lines) + PAD_X * 2)
            heights.append(len(lines) * LINE_HEIGHT + PAD_Y * 2)

        total_w = sum(widths) + NODE_GAP * (len(members) - 1)
        max_h = max(heights)
        x = MARGIN
        y = MARGIN + (ordered_ranks.index(rank)) * (max_h + RANK_GAP)

        for nid, w, h in zip(members, widths, heights):
            boxes.append(Box(
                id=nid,
                x=x,
                y=y + (max_h - h) / 2,
                w=w,
                h=h,
                fill=tactic_color.get(chain.nodes[nid].tactic, DEFAULT_COLOR),
                label_lines=labels[nid],
                on_path=nid in hl,
            ))
            x += w + NODE_GAP

    width = max((b.x + b.w for b in boxes), default=0) + MARGIN
    height = max((b.y + b.h for b in boxes), default=0) + MARGIN + 60   # 底部留给图例
    return boxes, width, height


def _topological(chain: Chain) -> List[str]:
    """拓扑排序。简单 Kahn 实现，避免额外依赖。"""
    indeg: Dict[str, int] = {nid: 0 for nid in chain.nodes}
    children: Dict[str, List[str]] = {nid: [] for nid in chain.nodes}
    for e in chain.edges:
        if e.src in indeg and e.dst in indeg:
            children[e.src].append(e.dst)
            indeg[e.dst] += 1
    queue = [n for n, d in indeg.items() if d == 0]
    order: List[str] = []
    while queue:
        n = queue.pop(0)
        order.append(n)
        for c in children[n]:
            indeg[c] -= 1
            if indeg[c] == 0:
                queue.append(c)
    return order


def _edge_points(a: Box, b: Box) -> Tuple[float, float, float, float, Tuple[float, float]]:
    """算一条边的起点、终点与箭头顶点。用三次贝塞尔让长距离连线更柔和。"""
    sx, sy = a.x + a.w / 2, a.y + a.h
    tx, ty = b.x + b.w / 2, b.y
    if ty < sy:      # 逆向边：从同一侧绕出，避免直线穿过节点
        sx, sy = a.x + a.w, a.y + a.h / 2
        tx, ty = b.x, b.y + b.h / 2
    return sx, sy, tx, ty, (tx, ty)


# ---------------------------------------------------------------- SVG


def render_svg(chain: Chain, boxes: List[Box], width: float, height: float,
               title: str = "") -> str:
    """手写 SVG。字体直接指定中文字体族，规避 Graphviz 的中文乱码问题。"""
    pos = {b.id: b for b in boxes}
    parts: List[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{int(width)}" height="{int(height)}" '
        f'viewBox="0 0 {int(width)} {int(height)}">',
        '<defs>',
        '<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
        'markerHeight="7" orient="auto-start-reverse">'
        '<path d="M 0 0 L 10 5 L 0 10 z" fill="#8A94A6"/></marker>',
        '<marker id="arrow-hot" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" '
        'markerHeight="8" orient="auto-start-reverse">'
        '<path d="M 0 0 L 10 5 L 0 10 z" fill="#D93025"/></marker>',
        '</defs>',
        f'<rect x="0" y="0" width="{int(width)}" height="{int(height)}" fill="#FFFFFF"/>',
        '<style>'
        'text{font-family:"Microsoft YaHei","Noto Sans CJK SC","PingFang SC",'
        '"Hiragino Sans GB","WenQuanYi Micro Hei",sans-serif;dominant-baseline:middle;}'
        '</style>',
    ]

    if title:
        parts.append(
            f'<text x="{MARGIN}" y="24" font-size="17" font-weight="bold" '
            f'fill="#1F2328">{html.escape(title)}</text>'
        )

    # 边先画，避免压住节点
    for e in chain.edges:
        if e.src not in pos or e.dst not in pos:
            continue
        a, b = pos[e.src], pos[e.dst]
        sx, sy, tx, ty, _ = _edge_points(a, b)
        hot = a.on_path and b.on_path
        color = "#D93025" if hot else "#8A94A6"
        stroke = 2.6 if hot else 1.4
        marker = "arrow-hot" if hot else "arrow"
        parts.append(
            f'<path d="M {sx:.1f} {sy:.1f} C {sx:.1f} {(sy + ty) / 2:.1f}, '
            f'{tx:.1f} {(sy + ty) / 2:.1f}, {tx:.1f} {ty:.1f}" '
            f'fill="none" stroke="{color}" stroke-width="{stroke}" marker-end="url(#{marker})"/>'
        )
        if e.condition:
            mx, my = (sx + tx) / 2, (sy + ty) / 2
            label = e.condition if len(e.condition) <= 18 else e.condition[:17] + "…"
            parts.append(
                f'<text x="{mx:.1f}" y="{my:.1f}" font-size="11" fill="#6E7781" '
                f'text-anchor="middle">{html.escape(label)}</text>'
            )

    # 节点
    for b in boxes:
        stroke = "#D93025" if b.on_path else "#57606A"
        sw = 2.4 if b.on_path else 1.0
        parts.append(
            f'<rect x="{b.x:.1f}" y="{b.y:.1f}" width="{b.w:.1f}" height="{b.h:.1f}" '
            f'rx="8" ry="8" fill="{b.fill}" stroke="{stroke}" stroke-width="{sw}"/>'
        )
        cx = b.x + b.w / 2
        start_y = b.y + PAD_Y + LINE_HEIGHT / 2
        for i, line in enumerate(b.label_lines):
            weight = "bold" if i == 0 else "normal"
            fs = FONT_SIZE if i == 0 else 11.5
            fill = "#1F2328" if i == 0 else "#57606A"
            parts.append(
                f'<text x="{cx:.1f}" y="{start_y + i * (LINE_HEIGHT if i == 0 else 16):.1f}" '
                f'font-size="{fs}" font-weight="{weight}" fill="{fill}" '
                f'text-anchor="middle">{html.escape(line)}</text>'
            )

    # 图例
    legend_y = height - 30
    parts.append(
        f'<text x="{MARGIN}" y="{legend_y:.1f}" font-size="12" fill="#57606A">'
        f'红线 = 当前最短攻击路径 ｜ 底色 = ATT&CK 战术阶段</text>'
    )
    parts.append("</svg>")
    return "\n".join(parts)


# ---------------------------------------------------------------- PNG


def _find_cjk_font() -> Optional[str]:
    """找系统中文字体。找不到就返回 None（Pillow 会用默认字体，中文会变方块）。"""
    candidates = [
        os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts", "msyh.ttc"),
        os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts", "msyhbd.ttc"),
        os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts", "simhei.ttf"),
        "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
        "/System/Library/Fonts/PingFang.ttc",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def render_png(chain: Chain, boxes: List[Box], width: float, height: float,
               out_path: str, title: str = "") -> Optional[str]:
    """用 Pillow 直接画 PNG。返回输出路径，Pillow 不可用时返回 None。"""
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        return None

    font_path = _find_cjk_font()
    def mk(size: int, bold: bool = False):
        if font_path:
            try:
                return ImageFont.truetype(font_path, size)
            except Exception:
                pass
        return ImageFont.load_default()

    f_title = mk(17, True)
    f_name = mk(14)
    f_small = mk(11)
    f_legend = mk(12)

    img = Image.new("RGB", (int(width), int(height)), "#FFFFFF")
    d = ImageDraw.Draw(img)

    if title:
        d.text((MARGIN, 16), title, fill="#1F2328", font=f_title)

    pos = {b.id: b for b in boxes}

    for e in chain.edges:
        if e.src not in pos or e.dst not in pos:
            continue
        a, b = pos[e.src], pos[e.dst]
        sx, sy, tx, ty, _ = _edge_points(a, b)
        hot = a.on_path and b.on_path
        color = (217, 48, 37) if hot else (138, 148, 166)
        d.line([(sx, sy), ((sx + tx) / 2, (sy + ty) / 2), (tx, ty)],
               fill=color, width=3 if hot else 1, joint="curve")
        # 箭头
        import math as _m
        ang = _m.atan2(ty - sy, tx - sx)
        L = 9
        d.polygon([
            (tx, ty),
            (tx - L * _m.cos(ang - 0.4), ty - L * _m.sin(ang - 0.4)),
            (tx - L * _m.cos(ang + 0.4), ty - L * _m.sin(ang + 0.4)),
        ], fill=color)

    for b in boxes:
        outline = (217, 48, 37) if b.on_path else (87, 96, 106)
        d.rounded_rectangle([b.x, b.y, b.x + b.w, b.y + b.h], radius=8,
                            fill=b.fill, outline=outline, width=3 if b.on_path else 1)
        cx = b.x + b.w / 2
        start_y = b.y + PAD_Y
        for i, line in enumerate(b.label_lines):
            font = f_name if i == 0 else f_small
            tw = _text_width(line, 14 if i == 0 else 11.5)
            d.text((cx - tw / 2, start_y + (0 if i == 0 else 18) + i * 16),
                   line, fill=(31, 35, 40) if i == 0 else (87, 96, 106), font=font)

    d.text((MARGIN, height - 30),
           "红线 = 当前最短攻击路径 ｜ 底色 = ATT&CK 战术阶段",
           fill=(87, 96, 106), font=f_legend)

    img.save(out_path, "PNG")
    return out_path


# ---------------------------------------------------------------- DOT / Mermaid


def render_dot(chain: Chain, tactic_color: Dict[str, str],
               highlight: Optional[Sequence[str]] = None) -> str:
    """导出 DOT 文本（不调用 dot 可执行文件）。

    保留 DOT 的意义是：用户机器上如果**有** Graphviz，可以拿去渲染成更精细的图；
    没有也不影响主流程。
    """
    lines = [
        "digraph AttackChain {",
        "  rankdir=TB;",
        '  graph [fontname="Microsoft YaHei", bgcolor="white"];',
        '  node [shape=box, style="rounded,filled", fontname="Microsoft YaHei"];',
    ]
    hl = set(highlight or [])
    for nid, node in chain.nodes.items():
        color = tactic_color.get(node.tactic, DEFAULT_COLOR)
        label = f"{node.name}\\n[{node.technique}]\\n检测:{node.detectability}"
        extra = ', color="#D93025", penwidth=2.5' if nid in hl else ""
        lines.append(f'  "{nid}" [label="{label}", fillcolor="{color}"{extra}];')
    for e in chain.edges:
        style = "bold,color=red" if (e.src in hl and e.dst in hl) else "color=gray"
        lines.append(f'  "{e.src}" -> "{e.dst}" [{style}];')
    lines.append("}")
    return "\n".join(lines)


def render_mermaid(chain: Chain, highlight: Optional[Sequence[str]] = None) -> str:
    """输出 Mermaid，可直接贴 GitHub Issue / Markdown 文档。"""
    hl = set(highlight or [])
    lines = ["flowchart TD"]
    for nid, node in chain.nodes.items():
        safe = node.name.replace('"', "'")
        lines.append(f'    {nid}["{safe} / {node.technique}"]')
    for e in chain.edges:
        if e.src in hl and e.dst in hl:
            lines.append(f"    {e.src} ==>|高亮| {e.dst}")
        else:
            lines.append(f"    {e.src} --> {e.dst}")
    for nid in hl:
        lines.append(f"    style {nid} stroke-width:3px,stroke:#D93025")
    return "\n".join(lines)


def try_render_dot_png(dot_text: str, out_png: str) -> Optional[str]:
    """系统里有 dot 就用它渲染 PNG，没有就静默跳过。"""
    dot_bin = shutil.which("dot")
    if not dot_bin:
        return None
    tmp = tempfile.NamedTemporaryFile("w", suffix=".dot", delete=False, encoding="utf-8")
    try:
        tmp.write(dot_text)
        tmp.close()
        subprocess.run([dot_bin, "-Tpng", tmp.name, "-o", out_png], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return out_png
    except Exception:
        return None
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


# ---------------------------------------------------------------- 统一入口


def render(chain: Chain, tactic_order: Dict[str, int], tactic_color: Dict[str, str],
           highlight: Optional[Sequence[str]], out_dir: str,
           formats: Sequence[str] = ("svg", "png", "dot", "mmd")) -> Dict[str, str]:
    """按指定格式渲染并落盘，返回 {格式: 路径}。"""
    os.makedirs(out_dir, exist_ok=True)
    boxes, width, height = layout(chain, tactic_order, tactic_color, highlight)
    title = chain.meta.name
    written: Dict[str, str] = {}

    if "svg" in formats:
        p = os.path.join(out_dir, "attack-chain.svg")
        with open(p, "w", encoding="utf-8") as fp:
            fp.write(render_svg(chain, boxes, width, height, title))
        written["svg"] = p

    if "png" in formats:
        p = os.path.join(out_dir, "attack-chain.png")
        if render_png(chain, boxes, width, height, p, title):
            written["png"] = p

    dot_text = render_dot(chain, tactic_color, highlight)
    if "dot" in formats:
        p = os.path.join(out_dir, "attack-chain.dot")
        with open(p, "w", encoding="utf-8") as fp:
            fp.write(dot_text)
        written["dot"] = p
    if "pdf" in formats:
        # PDF = 内置布局器渲染位图后经 Pillow 转换（此前误用 Graphviz PNG 充当 PDF，已修复）
        p = os.path.join(out_dir, "attack-chain.pdf")
        try:
            from PIL import Image
            tmp = p + ".tmp.png"
            if render_png(chain, boxes, width, height, tmp, title):
                Image.open(tmp).convert("RGB").save(p, "PDF", resolution=150.0)
                os.remove(tmp)
                written["pdf"] = p
        except Exception:
            pass  # Pillow 缺失或渲染失败时静默降级，不产生假 PDF
    if "gv-png" in formats:
        target = os.path.join(out_dir, "attack-chain-gv.png")
        got = try_render_dot_png(dot_text, target)
        if got:
            written["graphviz"] = got

    if "mmd" in formats:
        p = os.path.join(out_dir, "attack-chain.mmd")
        with open(p, "w", encoding="utf-8") as fp:
            fp.write(render_mermaid(chain, highlight))
        written["mmd"] = p

    return written
