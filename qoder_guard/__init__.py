"""Qoder guard layer (qoder_guard) -- external supervision for an untrusted
Qoder agent kernel.

Design philosophy: do not rely on Qoder policing itself (it lacks pre-execution
risk assessment, impact prediction, observability, permission tiers and an
audit dashboard). Just guarantee that even if it misbehaves it cannot hurt you.

Stage A (current): observe -- capture every tool-call event into the audit log
without blocking.
Stage B (next): block -- risk assessment + tiered gate + impact pre-analysis.
"""

__version__ = "0.1.3"
