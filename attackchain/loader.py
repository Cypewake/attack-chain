"""YAML 加载与字段校验。

目标：**解析出错时必须告诉用户错在 YAML 的第几行**，而不是抛一个 KeyError。
实现方式是给 PyYAML 的构造器打补丁，给每个 mapping 记录起始行号。
"""

from __future__ import annotations

import io
from typing import Any, Dict, List

import yaml

from .model import (
    Chain,
    ChainEdge,
    ChainNode,
    ChainError,
    DETECT_MEDIUM,
    KIND_FOOTHOLD,
    Meta,
    Objective,
)

__all__ = ["load_chain", "load_chain_file", "LineLoader"]


class LineLoader(yaml.SafeLoader):
    """记录行号的 SafeLoader。

    PyYAML 默认丢位置信息。这里重写 construct_mapping，把节点起始行号塞进
    私有键 `__line__`，构造数据模型时再取出来用。
    """


def _construct_mapping(loader: LineLoader, node: yaml.MappingNode, deep: bool = False):
    mapping: Dict[Any, Any] = {}
    if isinstance(node, yaml.MappingNode):
        # node.start_mark.line 是从 0 开始的，转成 1 起更符合编辑器习惯
        mapping["__line__"] = node.start_mark.line + 1
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        value = loader.construct_object(value_node, deep=deep)
        mapping[key] = value
    return mapping


LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def _where(line: Any, fallback: str) -> str:
    return f"第 {line} 行" if isinstance(line, int) else fallback


def _get(d: Dict[str, Any], key: str, default: Any = None) -> Any:
    value = d.get(key, default)
    return default if value is None else value


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def _parse_meta(raw: Dict[str, Any]) -> Meta:
    return Meta(
        name=_get(raw, "name", "未命名攻击链"),
        target=_get(raw, "target", ""),
        author=_get(raw, "author", ""),
        date=str(_get(raw, "date", "")),
        scenario=_get(raw, "scenario", ""),
    )


def _parse_objectives(raw_list: List[Dict[str, Any]]) -> Dict[str, Objective]:
    objectives: Dict[str, Objective] = {}
    for raw in raw_list:
        # 支持两种写法：完整 dict（id/name/tactic/note）或纯字符串 id
        if isinstance(raw, str):
            raw = {"id": raw}
        line = raw.get("__line__")
        oid = raw.get("id")
        if not oid:
            raise ChainError("目标缺少 id 字段", where=_where(line, "meta.objectives"))
        try:
            obj = Objective(
                id=oid,
                name=raw.get("name", oid),
                tactic=_get(raw, "tactic", "Privilege Escalation"),
                note=_get(raw, "note", ""),
            )
            obj.validate()
        except ChainError as exc:
            raise ChainError(str(exc), where=_where(line, f"目标 {oid}"))
        objectives[oid] = obj
    return objectives


def _parse_nodes(raw_list: List[Dict[str, Any]]) -> Dict[str, ChainNode]:
    nodes: Dict[str, ChainNode] = {}
    for raw in raw_list:
        line = raw.get("__line__")
        nid = raw.get("id")
        if not nid:
            raise ChainError("节点缺少 id 字段", where=_where(line, "nodes"))
        try:
            node = ChainNode(
                id=nid,
                name=raw.get("name", nid),
                tactic=raw.get("tactic", "Unknown"),
                technique=raw.get("technique", "T0000"),
                kind=_get(raw, "kind", KIND_FOOTHOLD),
                requires=_as_list(raw.get("requires")),
                optional=bool(raw.get("optional", False)),
                detectability=_get(raw, "detectability", DETECT_MEDIUM),
                detect_tips=_as_list(raw.get("detect_tips")),
                impact=int(_get(raw, "impact", 1)),
                fail_rate=float(_get(raw, "fail_rate", 0.3)),
                asset=_get(raw, "asset", ""),
                note=_get(raw, "note", ""),
            )
        except (ChainError, TypeError, ValueError) as exc:
            raise ChainError(str(exc), where=_where(line, f"节点 {nid}"))

        if nid in nodes:
            raise ChainError(
                f"节点 id '{nid}' 重复定义（前一个在第 "
                f"{nodes[nid].__dict__.get('_line', '?')} 行）",
                where=_where(line, f"节点 {nid}"),
            )
        node.__dict__["_line"] = line
        nodes[nid] = node
    return nodes


def _parse_edges(raw_list: List[Dict[str, Any]], nodes: Dict[str, ChainNode]) -> List[ChainEdge]:
    edges: List[ChainEdge] = []
    for raw in raw_list:
        line = raw.get("__line__")
        try:
            edge = ChainEdge(
                src=raw.get("src", ""),
                dst=raw.get("dst", ""),
                condition=_get(raw, "condition", ""),
                fail_rate=float(_get(raw, "fail_rate", 0.3)),
                note=_get(raw, "note", ""),
            )
            edge.validate()
        except (ChainError, TypeError, ValueError) as exc:
            raise ChainError(str(exc), where=_where(line, "edges"))

        # 越界引用在这里就挡住，避免到图计算阶段才炸
        for endpoint in (edge.src, edge.dst):
            if endpoint not in nodes:
                raise ChainError(
                    f"边 {edge.src}->{edge.dst} 引用了不存在的节点 '{endpoint}'",
                    where=_where(line, "edges"),
                )
        edges.append(edge)
    return edges


def load_chain(text: str) -> Chain:
    """从 YAML 文本加载攻击链。"""
    raw = yaml.load(io.StringIO(text), Loader=LineLoader)
    if not isinstance(raw, dict):
        raise ChainError("YAML 顶层必须是一个 mapping（meta / nodes / edges）")

    meta_raw = raw.get("meta") or {}
    if not isinstance(meta_raw, dict):
        raise ChainError("meta 必须是 mapping")

    meta = _parse_meta(meta_raw)
    objectives = _parse_objectives(list(raw.get("objectives") or meta_raw.get("objectives") or []))
    nodes = _parse_nodes(list(raw.get("nodes") or []))

    # 目标节点补齐：objectives 里声明但 nodes 里没有的，自动建一个 objective 节点
    for oid, obj in objectives.items():
        if oid not in nodes:
            nodes[oid] = ChainNode(
                id=oid,
                name=obj.name,
                tactic=obj.tactic,
                technique="T0000",
                kind="objective",
                detectability=DETECT_MEDIUM,
                impact=1,
            )

    edges = _parse_edges(list(raw.get("edges") or []), nodes)

    # requires 是隐式边：统一展开成显式 ChainEdge，图计算层就不用处理两种来源了
    known = {(e.src, e.dst) for e in edges}
    for node in nodes.values():
        for dep in node.requires:
            if (dep, node.id) not in known:
                edges.append(ChainEdge(src=dep, dst=node.id, condition="来自 requires"))
                known.add((dep, node.id))

    chain = Chain(meta=meta, nodes=nodes, edges=edges, objectives=objectives)
    chain.validate_graph()
    return chain


def load_chain_file(path: str) -> Chain:
    """从文件加载攻击链。"""
    try:
        with open(path, "r", encoding="utf-8") as fp:
            text = fp.read()
    except FileNotFoundError:
        raise ChainError(f"输入文件不存在: {path}")
    try:
        return load_chain(text)
    except ChainError as exc:
        raise ChainError(str(exc), where=f"{path} :: {exc.where or '顶层'}")
