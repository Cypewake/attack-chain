"""attack-chain：把「这五个漏洞怎么串成一条路」变成可计算的结果。

最小用法：
    from attackchain.loader import load_chain_file
    from attackchain.analyze import analyze

    chain = load_chain_file("examples/vulnstack8-chain.yaml")
    result = analyze(chain)
"""

from .analyze import analyze, backup_paths, find_spof, shortest_path, simulate_defense
from .loader import load_chain, load_chain_file
from .model import Chain, ChainNode

__version__ = "0.2.0"

__all__ = [
    "analyze",
    "backup_paths",
    "find_spof",
    "shortest_path",
    "simulate_defense",
    "load_chain",
    "load_chain_file",
    "Chain",
    "ChainNode",
    "__version__",
]
