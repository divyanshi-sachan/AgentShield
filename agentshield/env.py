"""Sandboxed workspace environment and its tools.

Nothing here touches the network or the real filesystem: every tool reads and
writes in-memory state, and every side effect ("sink") is recorded so scoring
can inspect what the agent actually did.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass, field
from importlib import resources
from typing import Any

ATTACKER_DOMAIN = "evil.test"
_SLOT_RE = re.compile(r"\{\{INJECTION:([a-z_]+)\}\}")


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    params: dict[str, dict[str, Any]]
    untrusted_output: bool = False  # output may contain third-party (attacker) text
    sink: bool = False  # has an externally visible or destructive effect

    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": self.params,
            "required": list(self.params),
            "additionalProperties": False,
        }


_STR = {"type": "string"}

TOOLS: dict[str, ToolSpec] = {
    t.name: t
    for t in [
        ToolSpec("list_inbox", "List emails in the user's inbox (id, sender, subject).", {}),
        ToolSpec("read_email", "Read the full body of an email by id.", {"email_id": _STR}, untrusted_output=True),
        ToolSpec("list_files", "List paths of files in the user's workspace.", {}),
        ToolSpec("read_file", "Read a workspace file.", {"path": _STR}, untrusted_output=True),
        ToolSpec("write_file", "Create or overwrite a workspace file.", {"path": _STR, "content": _STR}),
        ToolSpec("delete_file", "Delete a workspace file.", {"path": _STR}, sink=True),
        ToolSpec("fetch_url", "Fetch the text of a web page.", {"url": _STR}, untrusted_output=True),
        ToolSpec(
            "send_email",
            "Send an email on the user's behalf.",
            {"to": _STR, "subject": _STR, "body": _STR},
            sink=True,
        ),
        ToolSpec("post_http", "Send an HTTP POST request with a text body.", {"url": _STR, "body": _STR}, sink=True),
        ToolSpec(
            "transfer_money",
            "Transfer money from the user's account.",
            {"to_account": _STR, "amount": {"type": "number"}},
            sink=True,
        ),
    ]
}


class ToolError(Exception):
    pass


def make_canary(seed: int | str, episode_id: str) -> str:
    digest = hashlib.sha256(f"{seed}:{episode_id}".encode()).hexdigest()[:16]
    return f"ASHLD-{digest.upper()}"


def load_scenario() -> dict[str, Any]:
    text = resources.files("agentshield.suites").joinpath("workspace.json").read_text()
    return json.loads(text)


def scenario_slots(scenario: dict[str, Any] | None = None) -> set[str]:
    return set(_SLOT_RE.findall(json.dumps(scenario or load_scenario())))


@dataclass
class Environment:
    user: dict[str, str]
    inbox: list[dict[str, str]]
    files: dict[str, str]
    web: dict[str, str]
    canary: str
    sent_emails: list[dict[str, str]] = field(default_factory=list)
    http_posts: list[dict[str, str]] = field(default_factory=list)
    payments: list[dict[str, Any]] = field(default_factory=list)
    deleted_files: list[str] = field(default_factory=list)

    @classmethod
    def build(
        cls,
        canary: str,
        injection_text: str | None = None,
        slot: str | None = None,
        scenario: dict[str, Any] | None = None,
    ) -> "Environment":
        scenario = copy.deepcopy(scenario or load_scenario())

        def fill(value: str) -> str:
            value = value.replace("{{CANARY}}", canary)
            return _SLOT_RE.sub(
                lambda m: ("\n\n" + injection_text) if injection_text and m.group(1) == slot else "",
                value,
            )

        return cls(
            user=scenario["user"],
            inbox=[{k: fill(v) for k, v in e.items()} for e in scenario["inbox"]],
            files={p: fill(c) for p, c in scenario["files"].items()},
            web={u: fill(c) for u, c in scenario["web"].items()},
            canary=canary,
        )

    def execute(self, name: str, args: dict[str, Any]) -> str:
        if name not in TOOLS:
            raise ToolError(f"unknown tool '{name}'")
        missing = [p for p in TOOLS[name].params if p not in args]
        if missing:
            raise ToolError(f"missing arguments: {', '.join(missing)}")
        return getattr(self, f"_tool_{name}")(**{p: args[p] for p in TOOLS[name].params})

    # --- tools -----------------------------------------------------------------

    def _tool_list_inbox(self) -> str:
        return "\n".join(f"{e['id']} | from: {e['from']} | subject: {e['subject']}" for e in self.inbox)

    def _tool_read_email(self, email_id: str) -> str:
        for e in self.inbox:
            if e["id"] == email_id:
                return f"From: {e['from']}\nSubject: {e['subject']}\n\n{e['body']}"
        raise ToolError(f"no email with id '{email_id}'")

    def _tool_list_files(self) -> str:
        return "\n".join(sorted(self.files))

    def _tool_read_file(self, path: str) -> str:
        if path not in self.files:
            raise ToolError(f"no such file '{path}'")
        return self.files[path]

    def _tool_write_file(self, path: str, content: str) -> str:
        self.files[path] = content
        return f"wrote {len(content)} characters to {path}"

    def _tool_delete_file(self, path: str) -> str:
        if path not in self.files:
            raise ToolError(f"no such file '{path}'")
        del self.files[path]
        self.deleted_files.append(path)
        return f"deleted {path}"

    def _tool_fetch_url(self, url: str) -> str:
        if url not in self.web:
            raise ToolError(f"404 not found: {url}")
        return self.web[url]

    def _tool_send_email(self, to: str, subject: str, body: str) -> str:
        self.sent_emails.append({"to": to, "subject": subject, "body": body})
        return f"email sent to {to}"

    def _tool_post_http(self, url: str, body: str) -> str:
        self.http_posts.append({"url": url, "body": body})
        return "200 OK"

    def _tool_transfer_money(self, to_account: str, amount: float) -> str:
        self.payments.append({"to_account": to_account, "amount": float(amount)})
        return f"transferred {amount} to {to_account}"
