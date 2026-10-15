"""数据模型：纯标准库实现，不依赖任何第三方包。

设计约束（来自开发文档第三章分层设计原则）：
    model.py 不依赖第三方库 —— 方便单测、方便被其他模块/项目直接复用。
本文件只做「数据结构 + 字段合法性校验」，不做 IO、不做图计算。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

# ---------------------------------------------------------------- 枚举常量


#: 节点在攻击链中的角色
KIND_ENTRY = "entry"            # 入口：直接从外网可达，例如公网 Web 漏洞利用
KIND_FOOTHOLD = "foothold"      # 立足点：拿到执行能力，例如上传 webshell
KIND_LATERAL = "lateral"        # 横向：在内网里跳到其他主机
KIND_OBJECTIVE = "objective"    # 目标旗帜：例如域管理员权限
KIND_OPTIONAL = "optional"      # 可选：可放弃的旁路节点

VALID_KINDS = (KIND_ENTRY, KIND_FOOTHOLD, KIND_LATERAL, KIND_OBJECTIVE, KIND_OPTIONAL)

#: 防守方对该节点的可检测程度
DETECT_HIGH = "high"            # 有成熟检测手段（日志齐全、规则明确）
DETECT_MEDIUM = "medium"        # 需要一定分析成本或依赖特定数据源
DETECT_LOW = "low"              # 基本测不到，是攻击链的“舒适区”

VALID_DETECTABILITY = (DETECT_HIGH, DETECT_MEDIUM, DETECT_LOW)

#: 检测度到逃逸系数的映射：检测越强，这条边走起来越“贵”
#: （用于把防守视角折算进攻击侧的路径成本）
DETECT_COST = {DETECT_HIGH: 3.0, DETECT_MEDIUM: 1.5, DETECT_LOW: 0.5}


class ChainError(ValueError):
    """攻击链定义错误。携带定位信息，便于 loader 报出 YAML 行号。"""

    def __init__(self, message: str, where: str = ""):
        self.where = where
        super().__init__(f"{where + ': ' if where else ''}{message}")


# ---------------------------------------------------------------- 节点


@dataclass
class ChainNode:
    """攻击链上的一个技术节点（对应 ATT&CK 的一个技术/子技术）。"""

    id: str
    name: str
    tactic: str                             # ATT&CK 战术名，如 "Initial Access"
    technique: str                          # 技术编号，如 "T1190" / "T1505.003"
    kind: str = KIND_FOOTHOLD
    requires: List[str] = field(default_factory=list)   # 前置节点 id（入边来源）
    optional: bool = False                  # True 表示该节点可被放弃（旁路）
    detectability: str = DETECT_MEDIUM      # 防守方对本节点的检测能力
    detect_tips: List[str] = field(default_factory=list)
    impact: int = 1                         # 攻破该节点的“收益/重要性”，用于路径评分
    fail_rate: float = 0.3                  # 该节点自身的失败概率（0~1）
    asset: str = ""                         # 落点资产，如 "web01.example.com"
    note: str = ""

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        """字段级校验：缺字段、非法枚举、越界数值都要在这里挡住。"""
        if not self.id or not str(self.id).strip():
            raise ChainError("节点缺少 id", where="node")
        if not self.name:
            raise ChainError(f"节点 {self.id} 缺少 name", where="node")
        if self.kind not in VALID_KINDS:
            raise ChainError(
                f"节点 {self.id} 的 kind='{self.kind}' 非法，"
                f"可选值: {', '.join(VALID_KINDS)}",
                where="node",
            )
        if self.detectability not in VALID_DETECTABILITY:
            raise ChainError(
                f"节点 {self.id} 的 detectability='{self.detectability}' 非法，"
                f"可选值: {', '.join(VALID_DETECTABILITY)}",
                where="node",
            )
        if not 0.0 <= self.fail_rate < 1.0:
            raise ChainError(
                f"节点 {self.id} 的 fail_rate={self.fail_rate} 越界，需在 [0, 1) 区间",
                where="node",
            )
        if self.impact < 0:
            raise ChainError(f"节点 {self.id} 的 impact 不能为负数", where="node")
        if self.id in self.requires:
            raise ChainError(f"节点 {self.id} 的 requires 不能包含自身（自环）", where="node")


@dataclass
class ChainEdge:
    """节点之间的一次跃迁。"""

    src: str
    dst: str
    condition: str = ""         # 前置条件，如 "需要本地管理员权限"
    fail_rate: float = 0.3      # 该跃迁本身的失败概率（与节点区分，便于建模细微差别）
    note: str = ""

    def validate(self) -> None:
        if not self.src or not self.dst:
            raise ChainError(f"边缺少端点: {self.src} -> {self.dst}", where="edge")
        if self.src == self.dst:
            raise ChainError(f"边不能自环: {self.src}", where="edge")
        if not 0.0 <= self.fail_rate < 1.0:
            raise ChainError(
                f"边 {self.src}->{self.dst} 的 fail_rate={self.fail_rate} 越界",
                where="edge",
            )


@dataclass
class Objective:
    """目标旗帜。图分析到这里为止——它是防御方要保护的东西，也是 SPOF 分析中不应被删的节点。"""

    id: str
    name: str
    tactic: str = "Privilege Escalation"
    note: str = ""

    def validate(self) -> None:
        if not self.id or not self.name:
            raise ChainError("目标缺少 id 或 name", where="objective")


@dataclass
class Meta:
    """攻击链的元信息，用于报告抬头。"""

    name: str = "未命名攻击链"
    target: str = ""
    author: str = ""
    date: str = ""
    scenario: str = ""      # 场景说明：写清楚这是授权靶场还是真实演练


@dataclass
class Chain:
    """整条攻击链：元数据 + 节点 + 边 + 目标。"""

    meta: Meta
    nodes: Dict[str, ChainNode]
    edges: List[ChainEdge]
    objectives: Dict[str, Objective]

    # ---- 便捷查询 ----

    @property
    def entries(self) -> List[str]:
        """入口节点：显式标记为 entry 类型的节点。

        注意：这里只看 kind，不看入度。原因是有 YAML 会把中间节点也标记成 entry
        （比如"拿到内网主机后从这台机重新打点"），本工具尊重作者意图。
        """
        return [n.id for n in self.nodes.values() if n.kind == KIND_ENTRY]

    @property
    def objective_ids(self) -> List[str]:
        return list(self.objectives.keys())

    def node(self, node_id: str) -> ChainNode:
        try:
            return self.nodes[node_id]
        except KeyError:
            raise ChainError(f"引用了不存在的节点 '{node_id}'", where="resolve")

    def validate_graph(self) -> None:
        """整图校验：悬空引用、孤立节点、缺少入口/目标都要报出来。

        这一层必须放在 model 而不是 loader，因为图语义与文件格式无关
        （将来换成 JSON/数据库输入也能直接复用）。
        """
        if not self.nodes:
            raise ChainError("攻击链没有任何节点", where="chain")
        if not self.entries:
            raise ChainError(
                "攻击链没有任何入口节点（至少需要一个 kind: entry 的节点）", where="chain"
            )
        if not self.objectives:
            raise ChainError("攻击链没有目标（meta.objectives 为空）", where="chain")

        for nid, node in self.nodes.items():
            for dep in node.requires:
                if dep not in self.nodes:
                    raise ChainError(
                        f"节点 {nid} 依赖了不存在的节点 '{dep}'", where="chain"
                    )
        for edge in self.edges:
            edge.validate()
            if edge.src not in self.nodes:
                raise ChainError(f"边起点 '{edge.src}' 不存在", where="chain")
            if edge.dst not in self.nodes:
                raise ChainError(f"边终点 '{edge.dst}' 不存在", where="chain")
        for oid in self.objectives:
            if oid not in self.nodes:
                raise ChainError(
                    f"目标 '{oid}' 在 nodes 中没有对应节点，"
                    f"请为目标补一个 kind: objective 的节点",
                    where="chain",
                )
