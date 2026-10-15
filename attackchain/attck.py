"""ATT&CK 战术/技术映射库。

数据来源写在 JSON 里而不是打进代码，方便对照 ATT&CK 官方更新做 diff。
本模块只负责「查表」和「用检测结果反向补全建模者的疏漏」。
"""

from __future__ import annotations

import json
import os
from typing import Dict, List, Optional, Tuple

from .model import Chain, ChainNode

__all__ = ["AttckIndex", "load_default_index"]

DEFAULT_DATA_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "tactics.json"
)


class AttckIndex:
    """战术表 + 反向索引（技术编号 → 战术）。"""

    def __init__(self, data: dict):
        self.raw = data
        self.tactics: Dict[str, dict] = data.get("tactics", {})
        #: 技术编号 → 战术名。同一技术可能归属多个战术（如 T1505.003），保留最后一次
        self.technique_to_tactic: Dict[str, str] = {}
        for tactic_name, info in self.tactics.items():
            for technique_id in info.get("techniques", {}):
                self.technique_to_tactic[technique_id] = tactic_name

    # ---- 基础查询 ----

    @property
    def version(self) -> str:
        return self.raw.get("source", "unknown")

    def tactic_info(self, tactic: str) -> dict:
        return self.tactics.get(tactic, {})

    def name_zh(self, tactic: str) -> str:
        return self.tactic_info(tactic).get("name_zh", tactic)

    def tactic_id(self, tactic: str) -> str:
        return self.tactic_info(tactic).get("id", "")

    def color(self, tactic: str) -> str:
        return self.tactic_info(tactic).get("color", "#DDE3EA")

    def order(self, tactic: str) -> int:
        return int(self.tactic_info(tactic).get("order", 99))

    def data_sources(self, tactic: str) -> List[str]:
        return list(self.tactic_info(tactic).get("data_sources", []))

    def technique_name(self, technique: str, fallback: str = "") -> str:
        for tactic_name, info in self.tactics.items():
            techs = info.get("techniques", {})
            if technique in techs:
                return techs[technique]
        return fallback

    def has_technique(self, technique: str) -> bool:
        return technique in self.technique_to_tactic

    # ---- 一致性检查 ----

    def check(self, chain: Chain) -> List[dict]:
        """检查链定义与 ATT&CK 表的一致性，返回问题清单（不抛异常，作为报告的一部分）。

        检查两类问题：
          1. 未知技术编号 —— 可能是手抖打错字
          2. 技术编号与该节点声明的战术不匹配 —— ATT&CK 里同一个技术可能横跨多个战术，
             所以只报「完全不在该战术的任何技术里」，不断言唯一性
        """
        problems: List[dict] = []
        for node in chain.nodes.values():
            if not self.has_technique(node.technique):
                problems.append({
                    "node": node.id,
                    "level": "warning",
                    "message": f"技术编号 {node.technique} 不在本地 ATT&CK 子集里（可补充 data/tactics.json）",
                })
                continue
            declared = node.tactic
            mapped = self.technique_to_tactic[node.technique]
            techs_in_declared = self.tactic_info(declared).get("techniques", {})
            if node.technique not in techs_in_declared:
                problems.append({
                    "node": node.id,
                    "level": "warning",
                    "message": (
                        f"战术声明 '{declared}' 与本地表中 {node.technique} 的归属 "
                        f"'{mapped}' 不一致"
                    ),
                })
        return problems

    def enrich(self, chain: Chain) -> Tuple[Chain, List[str]]:
        """用战术表的检测数据源补全节点缺失的 detect_tips，返回被补全的节点列表。

        这是「工具帮你想」的地方：建模者常常只填了 detectability 忘了写检测手段，
        报告里给出通用数据源建议，比留空有用得多。
        """
        filled: List[str] = []
        for node in chain.nodes.values():
            if node.detect_tips:
                continue
            tips = self.data_sources(node.tactic)
            if tips:
                node.detect_tips = list(tips)
                filled.append(node.id)
        return chain, filled


def load_default_index(path: Optional[str] = None) -> AttckIndex:
    """加载 ATT&CK 战术表。找不到文件时不致命，降级为空表（图仍能画，只是没有中文名）。"""
    target = path or DEFAULT_DATA_PATH
    try:
        with open(target, "r", encoding="utf-8") as fp:
            return AttckIndex(json.load(fp))
    except (FileNotFoundError, json.JSONDecodeError):
        return AttckIndex({"tactics": {}})


def describe_node(index: AttckIndex, node: ChainNode) -> str:
    """给报告用的一行描述：`T1505.003 Web Shell（初始访问 TA0001）`"""
    name = index.technique_name(node.technique, fallback="未在本地表登记")
    tid = index.tactic_id(node.tactic)
    zh = index.name_zh(node.tactic)
    suffix = f"（{zh} {tid}）" if tid else ""
    return f"{node.technique} {name}{suffix}"
