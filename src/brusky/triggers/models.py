"""Shared data models for the trigger layer."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ChangedFile:
    path: str
    status: str  # "added" | "modified" | "removed"
    content: str = ""  # populated after fetching from Bitbucket API


@dataclass
class PREvent:
    repo_full_name: str       # "workspace/repo-slug"
    pr_id: int
    pr_title: str
    source_commit: str        # full commit hash
    source_branch: str
    destination_branch: str
    pr_url: str
    changed_files: list[ChangedFile] = field(default_factory=list)
