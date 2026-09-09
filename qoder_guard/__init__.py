"""Qoder guard layer (qoder_guard) -- external supervision for Qoder CLI.

Design philosophy: keep the safety checks outside the agent, so they hold
regardless of how the agent behaves. The five concerns this layer covers --
pre-execution risk assessment, impact prediction, observability, permission
tiers and an audit dashboard -- are implemented here rather than assumed to
be provided by the agent.

Stage A (current): observe -- capture every tool-call event into the audit log
without blocking.
Stage B (next): block -- risk assessment + tiered gate + impact pre-analysis.
"""

__version__ = "0.2.1"
