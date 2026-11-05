"""Documented stubs for 2 baselines that are NOT implemented yet.

They have the same interface as the other defenses (base.Defense), so they can be added
later without changes to the pipeline. Selecting them now stops with a clear error. No
result in this lab comes from these baselines.

G-Safeguard (Wang et al., 2025)
  Builds a graph of the agent messages, embeds each message, and trains a graph neural
  network to find poisoned agents; then it prunes their outgoing edges. To implement:
  (1) a message-embedding model, (2) labelled training runs (clean vs attacked traces from
  this lab), (3) a GNN (e.g. PyTorch Geometric), (4) check_handoff = drop or quarantine the
  message of an agent that the GNN flags. Not done: it needs a trained model and the
  training protocol of the paper.

Paul & Nandy (2026), architectural defenses (bib key paul2026beyond; arXiv ID still to verify)
  The paper text was not available to me, so the exact design is not known. Implement it
  after reading the paper; map each architectural control to system_suffix, render_logs,
  wrap_tool_output or check_handoff.
"""

from __future__ import annotations

from .base import Defense


class NotImplementedDefense(Defense):
    paper = ""

    def __init__(self) -> None:
        raise NotImplementedError(
            f"defense {self.name!r} ({self.paper}) is a documented stub; see src/soclab/defenses/stubs.py")


class GSafeguard(NotImplementedDefense):
    name = "g_safeguard"
    paper = "Wang et al. 2025"


class PaulNandy(NotImplementedDefense):
    name = "paul_nandy"
    paper = "Paul & Nandy 2026"
