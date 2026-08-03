#!/usr/bin/env python3
"""
AI Agent DFIR Framework

Offline forensic ingestion, enrichment, correlation, IOC extraction, analytics,
STIX export, and case replay reporting for AI coding-agent artifacts.

Python standard library only.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import html
import ipaddress
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import time
import uuid
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional
from urllib.parse import urlparse


TOOL_NAMES = ("codex", "claude", "gemini", "cursor", "windsurf", "continue", "aider", "copilot", "generic")
EVENT_ORDER = [
    "USER PROMPT", "ASSISTANT RESPONSE", "COMMAND", "FILE READ", "FILE CHANGE",
    "GIT", "APPROVAL", "TOOL", "MCP", "PLUGIN / SKILL", "NETWORK / API",
    "MODEL / TOKEN", "SECRET EXPOSURE", "WARNING / ERROR", "SESSION", "RUNTIME",
    "EXTERNAL TELEMETRY",
]
SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"(?<![A-Z0-9])(AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    "GitHub Token": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,255}\b"),
    "Slack Token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
    "Private Key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "Generic Credential": re.compile(r"(?i)\b(?:api[_-]?key|secret|token)\s*[:=]\s*['\"]?([^\s'\";,]{8,})"),
}
IOC_PATTERNS = {
    "url": re.compile(r"\bhttps?://[^\s<>'\"\]\)]+", re.I),
    "domain": re.compile(r"(?<![@/\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|ai|dev|app|cloud|local|internal|gov|edu|mil|biz|info|xyz|ru|cn|uk|de|fr|jp|au|ca|us)\b", re.I),
    "ipv4": re.compile(r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])"),
    "sha256": re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])"),
    "sha1": re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])"),
    "md5": re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])"),
    "aws_arn": re.compile(r"\barn:(?:aws|aws-us-gov|aws-cn):[A-Za-z0-9/_+=,.@:-]+\b"),
    "azure_resource": re.compile(r"/subscriptions/[0-9a-f-]{36}/resourceGroups/[^/\s]+/providers/[^\s\"']+", re.I),
    "gcp_project": re.compile(r"(?i)\bproject(?:_id)?\s*[:=]\s*['\"]?([a-z][a-z0-9-]{4,28}[a-z0-9])"),
    "registry": re.compile(r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\[^\r\n\"']+", re.I),
}
WINDOWS_PATH_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9_])([A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)+[^\\/:*?\"<>|\r\n]*)"
)
POSIX_PATH_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9_])(/(?:[^/\s<>\"']+/)+[^/\s<>\"']*)"
)
COMMAND_MARKERS = re.compile(r"(?i)\b(?:powershell|pwsh|cmd(?:\.exe)?|bash|zsh|sh|python(?:3)?|node|npm|git|curl|wget|kubectl|aws|az|gcloud)\b")
GIT_PATTERN = re.compile(r"(?i)(?:^|\s)git\s+(clone|checkout|switch|status|diff|add|commit|push|pull|fetch|merge|rebase|reset|restore|log|show)\b")
WRITE_PATTERN = re.compile(r"(?i)\b(?:apply_patch|write_file|create_file|replace_in_file|edit_file|file[_ /-]?write|patch)\b")
READ_PATTERN = re.compile(r"(?i)\b(?:read_file|cat|type|get-content|sed\s+-n|head|tail|open_file|view_file)\b")
NETWORK_PATTERN = re.compile(r"(?i)\b(?:https?://|curl|wget|Invoke-WebRequest|Invoke-RestMethod|api\b|websocket|SSE|DNS)\b")
APPROVAL_PATTERN = re.compile(r"(?i)\b(?:approval|approved|denied|permission|authorize|confirmation)\b")


@dataclass
class Event:
    timestamp_utc: str = ""
    agent: str = "generic"
    category: str = "Runtime"
    action: str = ""
    text: str = ""
    details: str = ""
    username: str = ""
    hostname: str = ""
    session_id: str = ""
    turn_id: str = ""
    call_id: str = ""
    process_id: str = ""
    tool_name: str = ""
    model: str = ""
    working_directory: str = ""
    target: str = ""
    level: str = ""
    source_type: str = ""
    source_file: str = ""
    source_line: str = ""
    evidence_hash: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def searchable_text(self) -> str:
        return "\n".join([
            self.category, self.action, self.text, self.details, self.tool_name,
            self.model, self.working_directory, self.target,
        ])


def iso_utc(value: Any) -> str:
    if value is None or value == "":
        return ""
    if isinstance(value, (int, float)):
        # Handle seconds and milliseconds.
        seconds = float(value)
        if seconds > 10_000_000_000:
            seconds /= 1000.0
        try:
            return dt.datetime.fromtimestamp(seconds, tz=dt.timezone.utc).isoformat()
        except (ValueError, OSError, OverflowError):
            return str(value)
    text = str(value).strip()
    if not text:
        return ""
    try:
        normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
        parsed = dt.datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc).isoformat()
    except ValueError:
        return text


def parse_timestamp(value: str) -> Optional[dt.datetime]:
    normalized = iso_utc(value)
    try:
        parsed = dt.datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc)
    except (ValueError, TypeError):
        return None


def hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def flatten_text(value: Any, max_depth: int = 8) -> str:
    pieces: list[str] = []
    def walk(node: Any, depth: int) -> None:
        if depth > max_depth or node is None:
            return
        if isinstance(node, str):
            pieces.append(node)
        elif isinstance(node, (int, float, bool)):
            pieces.append(str(node))
        elif isinstance(node, dict):
            for key, child in node.items():
                if key.lower() not in {"embedding", "image", "audio", "bytes", "base64"}:
                    walk(child, depth + 1)
        elif isinstance(node, list):
            for child in node:
                walk(child, depth + 1)
    walk(value, 0)
    return "\n".join(pieces)


def first_value(node: Any, keys: Iterable[str]) -> Any:
    wanted = {k.lower() for k in keys}
    queue = [node]
    while queue:
        current = queue.pop(0)
        if isinstance(current, dict):
            for key, value in current.items():
                if key.lower() in wanted and value not in (None, "", [], {}):
                    return value
                if isinstance(value, (dict, list)):
                    queue.append(value)
        elif isinstance(current, list):
            queue.extend(v for v in current if isinstance(v, (dict, list)))
    return ""


def extract_role_text(record: dict[str, Any]) -> tuple[str, str]:
    role = str(first_value(record, ["role", "sender", "author_role"])).lower()
    candidates: list[str] = []
    for key in ("content", "text", "message", "prompt", "response", "body"):
        value = record.get(key)
        if isinstance(value, str):
            candidates.append(value)
        elif isinstance(value, (list, dict)):
            candidates.append(flatten_text(value))
    payload = record.get("payload")
    if isinstance(payload, dict):
        content = payload.get("content")
        if isinstance(content, (dict, list, str)):
            candidates.append(flatten_text(content))
    return role, next((x.strip() for x in candidates if x and x.strip()), "")


def normalized_event_from_mapping(row: dict[str, Any], source: Path, line: int = 0) -> Event:
    def get(*names: str) -> str:
        for name in names:
            if name in row and row[name] not in (None, ""):
                return str(row[name])
        lower = {str(k).lower(): v for k, v in row.items()}
        for name in names:
            value = lower.get(name.lower())
            if value not in (None, ""):
                return str(value)
        return ""
    text = get("Text", "text", "Evidence", "evidence", "message")
    details = get("Details", "details")
    return Event(
        timestamp_utc=iso_utc(get("TimestampUtc", "timestamp_utc", "timestamp", "time", "ts")),
        agent=get("Agent", "agent") or "codex",
        category=get("Category", "category") or "Runtime",
        action=get("Action", "action"),
        text=text,
        details=details,
        username=get("Username", "username", "user"),
        hostname=get("Hostname", "hostname", "computer"),
        session_id=get("ThreadId", "SessionId", "session_id", "thread_id"),
        turn_id=get("TurnId", "turn_id"),
        call_id=get("CallId", "call_id"),
        process_id=get("ProcessUuid", "ProcessId", "process_id"),
        tool_name=get("ToolName", "tool_name"),
        model=get("Model", "model"),
        working_directory=get("WorkingDirectory", "working_directory", "cwd"),
        target=get("Target", "target"),
        level=get("Level", "level"),
        source_type=get("Source", "source_type") or "normalized",
        source_file=str(source),
        source_line=str(line or get("LineNumber", "source_line")),
        evidence_hash=hash_text(text + "\n" + details),
        metadata={k: v for k, v in row.items() if str(k) not in {
            "TimestampUtc", "Text", "Details", "Category", "Action"
        }},
    )


class Adapter:
    name = "generic"
    priority = 0

    def matches(self, path: Path, sample: str = "") -> bool:
        return False

    def parse(self, path: Path) -> Iterator[Event]:
        raise NotImplementedError


class NormalizedTimelineAdapter(Adapter):
    name = "normalized"
    priority = 100

    def matches(self, path: Path, sample: str = "") -> bool:
        return path.name.lower() in {"codex_timeline.jsonl", "codex_timeline.csv", "ai_timeline.jsonl", "ai_timeline.csv"}

    def parse(self, path: Path) -> Iterator[Event]:
        if path.suffix.lower() == ".csv":
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                for idx, row in enumerate(csv.DictReader(handle), 2):
                    yield normalized_event_from_mapping(dict(row), path, idx)
        else:
            with path.open("r", encoding="utf-8-sig") as handle:
                for idx, line in enumerate(handle, 1):
                    if not line.strip():
                        continue
                    item = json.loads(line)
                    if isinstance(item, dict):
                        yield normalized_event_from_mapping(item, path, idx)


class CodexSessionAdapter(Adapter):
    name = "codex"
    priority = 90

    def matches(self, path: Path, sample: str = "") -> bool:
        lower = str(path).lower()
        return path.suffix.lower() == ".jsonl" and (".codex" in lower or "sessions" in lower) and '"payload"' in sample

    def parse(self, path: Path) -> Iterator[Event]:
        with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
            for idx, line in enumerate(handle, 1):
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                payload = obj.get("payload", {}) if isinstance(obj, dict) else {}
                role, text = extract_role_text(payload if isinstance(payload, dict) else obj)
                timestamp = first_value(obj, ["timestamp", "created_at", "ts", "time"])
                event = Event(
                    timestamp_utc=iso_utc(timestamp),
                    agent="codex",
                    username=str(first_value(obj, ["username", "user"])),
                    hostname=str(first_value(obj, ["hostname", "computer"])),
                    session_id=str(first_value(obj, ["thread_id", "session_id", "conversation_id"])),
                    turn_id=str(first_value(obj, ["turn_id", "id"])),
                    call_id=str(first_value(obj, ["call_id"])),
                    process_id=str(first_value(obj, ["process_uuid", "process_id"])),
                    tool_name=str(first_value(obj, ["tool_name", "name"])),
                    model=str(first_value(obj, ["model"])),
                    working_directory=str(first_value(obj, ["cwd", "working_directory"])),
                    source_type="codex_session_jsonl",
                    source_file=str(path),
                    source_line=str(idx),
                    metadata={
                        "record_type": obj.get("type", "") if isinstance(obj, dict) else "",
                        "role": role,
                        "conversation_eligible": bool(
                            role in {"user", "human", "assistant", "ai"} and text
                        ),
                        "conversation_source": "raw_session_jsonl",
                    },
                )
                if isinstance(payload, dict):
                    info = payload.get("info", {})
                    total_usage = info.get("total_token_usage", {}) if isinstance(info, dict) else {}
                    if isinstance(total_usage, dict):
                        event.metadata.update({
                            "input_tokens": total_usage.get("input_tokens", ""),
                            "cached_input_tokens": total_usage.get("cached_input_tokens", ""),
                            "output_tokens": total_usage.get("output_tokens", ""),
                            "reasoning_output_tokens": total_usage.get("reasoning_output_tokens", ""),
                            "total_tokens": total_usage.get("total_tokens", ""),
                            "token_usage_kind": "cumulative",
                        })
                combined = flatten_text(obj)
                if role in {"user", "human"} and text and not text.lstrip().startswith("<"):
                    event.category, event.action, event.text = "Prompt", "UserInput", text
                elif role in {"assistant", "ai"} and text:
                    event.category, event.action, event.text = "AssistantMessage", "AssistantOutput", text
                elif event.tool_name or re.search(r"function_call|tool_call|exec_command|apply_patch", combined, re.I):
                    event.category, event.action, event.details = "ToolOrAction", "ToolEvent", combined[:20000]
                else:
                    event.category, event.action, event.details = "SessionOrTurn", "SessionEvent", combined[:20000]
                event.evidence_hash = hash_text(event.text + "\n" + event.details)
                yield event



class GeminiAntigravityAdapter(Adapter):
    """Parser for Gemini Antigravity CLI transcript_full.jsonl files."""

    name = "gemini-antigravity"
    priority = 95

    def matches(self, path: Path, sample: str = "") -> bool:
        lower = str(path).replace("\\", "/").lower()
        if path.suffix.lower() not in {".jsonl", ".ndjson"}:
            return False
        if "/.gemini/antigravity-cli/brain/" not in lower:
            return False
        return (
            path.name.lower() == "transcript_full.jsonl"
            or (
                '"step_index"' in sample
                and '"source"' in sample
                and '"type"' in sample
                and '"created_at"' in sample
            )
        )

    @staticmethod
    def session_id_from_path(path: Path) -> str:
        parts = list(path.parts)
        lower_parts = [part.lower() for part in parts]
        try:
            brain_index = lower_parts.index("brain")
            if brain_index + 1 < len(parts):
                return parts[brain_index + 1]
        except ValueError:
            pass
        return path.parent.parent.name or path.stem

    @staticmethod
    def extract_user_request(content: str) -> str:
        if not content:
            return ""
        match = re.search(r"<USER_REQUEST>\s*(.*?)\s*</USER_REQUEST>", content, re.I | re.S)
        if match:
            return match.group(1).strip()
        return content.strip()

    @staticmethod
    def compact_tool_details(name: str, args: dict[str, Any]) -> str:
        safe_args: dict[str, Any] = {}
        for key, value in args.items():
            # Keep forensic metadata, but avoid flooding the Timeline with entire
            # source files. The target, description, command, and summary retain
            # the useful activity context.
            if key in {"CodeContent", "Base64", "ImageBytes"}:
                if isinstance(value, str):
                    safe_args[key + "Length"] = len(value)
                    safe_args[key + "SHA256"] = hash_text(value)
                continue
            safe_args[key] = value
        return json.dumps(
            {"tool_name": name, "args": safe_args},
            ensure_ascii=False,
            default=str,
        )

    def parse(self, path: Path) -> Iterator[Event]:
        session_id = self.session_id_from_path(path)

        with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
            for idx, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(obj, dict):
                    continue

                timestamp = iso_utc(obj.get("created_at", ""))
                step_index = str(obj.get("step_index", ""))
                source = str(obj.get("source", "")).upper()
                record_type = str(obj.get("type", "")).upper()
                status = str(obj.get("status", ""))
                content = str(obj.get("content", "") or "")
                thinking = str(obj.get("thinking", "") or "")

                base_metadata = {
                    "record_type": record_type,
                    "gemini_source": source,
                    "status": status,
                    "step_index": step_index,
                    "conversation_source": "raw_gemini_transcript_jsonl",
                }

                if source == "USER_EXPLICIT" and record_type == "USER_INPUT":
                    message = self.extract_user_request(content)
                    if message:
                        yield Event(
                            timestamp_utc=timestamp,
                            agent="gemini",
                            category="Prompt",
                            action="UserInput",
                            text=message,
                            session_id=session_id,
                            turn_id=step_index,
                            source_type="gemini_antigravity_jsonl",
                            source_file=str(path),
                            source_line=str(idx),
                            evidence_hash=hash_text(line),
                            metadata={
                                **base_metadata,
                                "role": "user",
                                "conversation_eligible": True,
                            },
                        )
                    continue

                # A PLANNER_RESPONSE with final content is Gemini's user-facing
                # assistant response. Planner thinking without content remains
                # Timeline evidence, not Case Replay.
                if source == "MODEL" and record_type == "PLANNER_RESPONSE" and content.strip():
                    yield Event(
                        timestamp_utc=timestamp,
                        agent="gemini",
                        category="AssistantMessage",
                        action="AssistantOutput",
                        text=content.strip(),
                        session_id=session_id,
                        turn_id=step_index,
                        source_type="gemini_antigravity_jsonl",
                        source_file=str(path),
                        source_line=str(idx),
                        evidence_hash=hash_text(line),
                        metadata={
                            **base_metadata,
                            "role": "assistant",
                            "conversation_eligible": True,
                        },
                    )

                tool_calls = obj.get("tool_calls", [])
                if isinstance(tool_calls, list):
                    for tool_index, tool_call in enumerate(tool_calls):
                        if not isinstance(tool_call, dict):
                            continue
                        tool_name = str(tool_call.get("name", "") or "")
                        args = tool_call.get("args", {})
                        if not isinstance(args, dict):
                            args = {"value": args}

                        command = str(args.get("CommandLine", "") or "")
                        cwd = str(args.get("Cwd", "") or "")
                        target = str(
                            args.get("TargetFile", "")
                            or args.get("DirectoryPath", "")
                            or args.get("Target", "")
                            or args.get("ImageName", "")
                            or ""
                        )

                        if tool_name == "run_command":
                            category, action = "ToolOrAction", "exec_command"
                        elif tool_name == "write_to_file":
                            category, action = "ToolOrAction", "write_file"
                        elif tool_name == "list_dir":
                            category, action = "ToolOrAction", "read_file"
                        elif tool_name == "ask_permission":
                            category, action = "ToolOrAction", "approval_request"
                        else:
                            category, action = "ToolOrAction", tool_name or "ToolEvent"

                        metadata = {
                            **base_metadata,
                            "role": "",
                            "conversation_eligible": False,
                            "tool_call_index": tool_index,
                            "tool_args": args,
                        }
                        if command:
                            metadata["command"] = command

                        yield Event(
                            timestamp_utc=timestamp,
                            agent="gemini",
                            category=category,
                            action=action,
                            details=self.compact_tool_details(tool_name, args),
                            session_id=session_id,
                            turn_id=step_index,
                            call_id=f"{step_index}:{tool_index}",
                            tool_name=tool_name,
                            working_directory=cwd,
                            target=target,
                            source_type="gemini_antigravity_jsonl",
                            source_file=str(path),
                            source_line=str(idx),
                            evidence_hash=hash_text(
                                line + f"\nTOOL_INDEX={tool_index}"
                            ),
                            metadata=metadata,
                        )

                if thinking.strip():
                    yield Event(
                        timestamp_utc=timestamp,
                        agent="gemini",
                        category="SessionOrTurn",
                        action="ModelReasoning",
                        details=thinking.strip(),
                        session_id=session_id,
                        turn_id=step_index,
                        source_type="gemini_antigravity_jsonl",
                        source_file=str(path),
                        source_line=str(idx),
                        evidence_hash=hash_text(line + "\nTHINKING"),
                        metadata={
                            **base_metadata,
                            "role": "",
                            "conversation_eligible": False,
                            "reasoning": True,
                        },
                    )

                # Tool result, checkpoint, and system records are preserved in
                # Timeline but never admitted to Case Replay.
                if content.strip() and not (
                    source == "USER_EXPLICIT" and record_type == "USER_INPUT"
                ) and not (
                    source == "MODEL"
                    and record_type == "PLANNER_RESPONSE"
                ):
                    action = record_type or "GeminiRecord"
                    category = (
                        "ToolOrAction"
                        if source == "MODEL" and record_type not in {"CHECKPOINT", "CONVERSATION_HISTORY"}
                        else "SessionOrTurn"
                    )
                    yield Event(
                        timestamp_utc=timestamp,
                        agent="gemini",
                        category=category,
                        action=action,
                        details=content[:20000],
                        session_id=session_id,
                        turn_id=step_index,
                        source_type="gemini_antigravity_jsonl",
                        source_file=str(path),
                        source_line=str(idx),
                        evidence_hash=hash_text(line),
                        metadata={
                            **base_metadata,
                            "role": "system" if source == "SYSTEM" else "",
                            "conversation_eligible": False,
                        },
                    )


class GenericJsonlAgentAdapter(Adapter):
    name = "multi-agent-jsonl"
    priority = 40

    AGENT_HINTS = {
        "claude": (".claude", "claude"),
        "gemini": (".gemini", "gemini"),
        "aider": (".aider", "aider"),
        "continue": (".continue", "continue"),
        "cursor": (".cursor", "cursor"),
        "windsurf": (".windsurf", "windsurf"),
        "copilot": ("copilot",),
    }

    def identify(self, path: Path) -> str:
        lower = str(path).lower()
        for agent, hints in self.AGENT_HINTS.items():
            if any(h in lower for h in hints):
                return agent
        return "codex"

    def matches(self, path: Path, sample: str = "") -> bool:
        return path.suffix.lower() in {".jsonl", ".ndjson"} and bool(sample.strip().startswith("{"))

    def parse(self, path: Path) -> Iterator[Event]:
        agent = self.identify(path)
        with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
            for idx, line in enumerate(handle, 1):
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(obj, dict):
                    continue
                role, text = extract_role_text(obj)
                combined = flatten_text(obj)
                category, action = "Runtime", str(first_value(obj, ["type", "event", "action"]))
                if role in {"user", "human"} and text:
                    category, action = "Prompt", "UserInput"
                elif role in {"assistant", "ai", "model"} and text:
                    category, action = "AssistantMessage", "AssistantOutput"
                elif first_value(obj, ["tool_name", "function_name", "command"]) or re.search(r"tool|command|shell|patch", combined, re.I):
                    category, action = "ToolOrAction", action or "ToolEvent"
                yield Event(
                    timestamp_utc=iso_utc(first_value(obj, ["timestamp", "created_at", "time", "ts"])),
                    agent=agent,
                    category=category,
                    action=action,
                    text=text if category in {"Prompt", "AssistantMessage"} else "",
                    details=combined[:20000] if category not in {"Prompt", "AssistantMessage"} else "",
                    username=str(first_value(obj, ["username", "user_name"])),
                    hostname=str(first_value(obj, ["hostname", "computer"])),
                    session_id=str(first_value(obj, ["session_id", "conversation_id", "thread_id", "chat_id"])),
                    turn_id=str(first_value(obj, ["turn_id", "message_id", "id"])),
                    call_id=str(first_value(obj, ["call_id", "tool_call_id"])),
                    process_id=str(first_value(obj, ["process_id", "process_uuid"])),
                    tool_name=str(first_value(obj, ["tool_name", "function_name", "name"])),
                    model=str(first_value(obj, ["model", "model_name"])),
                    working_directory=str(first_value(obj, ["cwd", "working_directory", "project_path"])),
                    source_type=f"{agent}_jsonl",
                    source_file=str(path),
                    source_line=str(idx),
                    evidence_hash=hash_text(text + "\n" + combined),
                    metadata={"adapter_confidence": "best-effort"},
                )


class GenericJsonAdapter(Adapter):
    name = "multi-agent-json"
    priority = 30

    def matches(self, path: Path, sample: str = "") -> bool:
        return path.suffix.lower() == ".json" and sample.lstrip().startswith(("{", "["))

    def parse(self, path: Path) -> Iterator[Event]:
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
        except json.JSONDecodeError:
            return
        records = data if isinstance(data, list) else [data]
        # Reuse generic extraction, including nested message arrays.
        expanded: list[dict[str, Any]] = []
        for record in records:
            if isinstance(record, dict):
                expanded.append(record)
                for key in ("messages", "history", "conversation", "turns", "items"):
                    nested = record.get(key)
                    if isinstance(nested, list):
                        expanded.extend(x for x in nested if isinstance(x, dict))
        lower = str(path).lower()
        agent = next((a for a in TOOL_NAMES if a != "generic" and a in lower), "codex")
        for idx, obj in enumerate(expanded, 1):
            role, text = extract_role_text(obj)
            if not text:
                continue
            category = "Prompt" if role in {"user", "human"} else "AssistantMessage" if role in {"assistant", "ai", "model"} else "Runtime"
            yield Event(
                timestamp_utc=iso_utc(first_value(obj, ["timestamp", "created_at", "time", "ts"])),
                agent=agent,
                category=category,
                action="UserInput" if category == "Prompt" else "AssistantOutput" if category == "AssistantMessage" else "Record",
                text=text if category != "Runtime" else "",
                details=flatten_text(obj)[:20000] if category == "Runtime" else "",
                session_id=str(first_value(obj, ["session_id", "conversation_id", "thread_id", "chat_id"])),
                turn_id=str(first_value(obj, ["turn_id", "message_id", "id"])),
                model=str(first_value(obj, ["model", "model_name"])),
                working_directory=str(first_value(obj, ["cwd", "working_directory", "project_path"])),
                source_type=f"{agent}_json",
                source_file=str(path),
                source_line=str(idx),
                evidence_hash=hash_text(text),
                metadata={"adapter_confidence": "best-effort"},
            )


class SQLiteAdapter(Adapter):
    name = "sqlite"
    priority = 80

    def matches(self, path: Path, sample: str = "") -> bool:
        return path.suffix.lower() in {".sqlite", ".sqlite3", ".db"} or path.name.lower().startswith("logs_")

    def parse(self, path: Path) -> Iterator[Event]:
        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        except sqlite3.Error:
            return
        try:
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            for table in tables:
                safe_table = table.replace('"', '""')
                try:
                    columns = [r[1] for r in conn.execute(f'PRAGMA table_info("{safe_table}")')]
                except sqlite3.Error:
                    continue
                if not columns:
                    continue
                lower_cols = {c.lower(): c for c in columns}
                body_col = next((lower_cols[c] for c in ("feedback_log_body", "body", "message", "text", "content") if c in lower_cols), None)
                if not body_col:
                    continue
                ts_col = next((lower_cols[c] for c in ("timestamp", "created_at", "ts", "time") if c in lower_cols), None)
                level_col = lower_cols.get("level")
                target_col = lower_cols.get("target")
                thread_col = lower_cols.get("thread_id")
                process_col = lower_cols.get("process_uuid")
                selected = [body_col] + [c for c in (ts_col, level_col, target_col, thread_col, process_col) if c]
                query = "SELECT rowid," + ",".join(f'"{c}"' for c in selected) + f' FROM "{safe_table}"'
                try:
                    cursor = conn.execute(query)
                except sqlite3.Error:
                    continue
                for row in cursor:
                    mapping = dict(zip(["rowid"] + selected, row))
                    body = str(mapping.get(body_col, "") or "")
                    if not body:
                        continue
                    role = ""
                    prompt_match = re.search(r"(?is)(?:UserInput|user[_ ]?prompt|submission).*?(?:text|content)\s*[:=]\s*[\"'](.{1,10000}?)[\"'](?:[,}\]])", body)
                    category, action, text = "Runtime", "SQLiteRecord", ""
                    if prompt_match:
                        category, action, text = "Prompt", "UserInput", prompt_match.group(1)
                    elif re.search(r"(?i)assistant|response.output_text", body):
                        category, action = "AssistantMessage", "AssistantOutput"
                    elif re.search(r"(?i)tool|command|apply_patch|approval|mcp", body):
                        category, action = "ToolOrAction", "RuntimeToolEvent"
                    yield Event(
                        timestamp_utc=iso_utc(mapping.get(ts_col, "") if ts_col else ""),
                        agent="codex",
                        category=category,
                        action=action,
                        text=text,
                        details=body[:20000],
                        level=str(mapping.get(level_col, "") if level_col else ""),
                        target=str(mapping.get(target_col, "") if target_col else ""),
                        session_id=str(mapping.get(thread_col, "") if thread_col else ""),
                        process_id=str(mapping.get(process_col, "") if process_col else ""),
                        source_type=f"sqlite:{table}",
                        source_file=str(path),
                        source_line=str(mapping["rowid"]),
                        evidence_hash=hash_text(body),
                        metadata={
                            "table": table,
                            "conversation_eligible": False,
                            "conversation_source": "sqlite_runtime",
                        },
                    )
        finally:
            conn.close()


ADAPTERS = sorted([
    GeminiAntigravityAdapter(), CodexSessionAdapter(), SQLiteAdapter(),
    GenericJsonlAgentAdapter(), GenericJsonAdapter(),
], key=lambda a: a.priority, reverse=True)


def discover_files(root: Path) -> list[Path]:
    generated = {
        "codex_timeline.csv", "codex_timeline.jsonl",
        "codex_prompts.jsonl", "codex_assistantmessages.jsonl",
        "codex_toolactivity.jsonl", "ai_agent_timeline.csv",
        "ai_agent_timeline.jsonl", "case_replay.csv", "analytics.json",
        "indicators.csv", "indicators_stix_2.1.json",
        "ingestion_diagnostics.csv", "summary.json", "artifact_inventory.csv",
        "sha256sums.txt",
    }

    def allowed(path: Path) -> bool:
        name = path.name.lower()
        low = str(path).replace("\\", "/").lower()
        if name in generated or name.endswith(("-wal", "-shm")):
            return False
        if path.suffix.lower() in {".jsonl", ".ndjson"}:
            return (
                "/.codex/sessions/" in low
                or name == "session_index.jsonl"
                or (
                    "/.gemini/antigravity-cli/brain/" in low
                    and "/.system_generated/logs/" in low
                    and name == "transcript_full.jsonl"
                )
            )
        if path.suffix.lower() in {".sqlite", ".sqlite3", ".db"}:
            return True
        if path.suffix.lower() == ".json":
            return any(x in low for x in (
                "/.claude/", "/.gemini/", "/.cursor/", "/.windsurf/",
                "/.continue/", "/.aider/",
            ))
        return False

    if root.is_file():
        return [root] if allowed(root) else []
    return [path for path in root.rglob("*") if path.is_file() and allowed(path)]


def materialize_input(path: Path) -> tuple[Path, Optional[tempfile.TemporaryDirectory[str]]]:
    if path.is_file() and path.suffix.lower() == ".zip":
        temp = tempfile.TemporaryDirectory(prefix="aia_dfir_")
        with zipfile.ZipFile(path) as archive:
            archive.extractall(temp.name)
        return Path(temp.name), temp
    return path, None


def ingest(paths: list[Path]) -> tuple[list[Event], list[dict[str, str]]]:
    events: list[Event] = []
    diagnostics: list[dict[str, str]] = []
    seen_files: set[str] = set()
    for supplied in paths:
        materialized, temp = materialize_input(supplied)
        try:
            for file_path in discover_files(materialized):
                resolved = str(file_path.resolve())
                if resolved in seen_files:
                    continue
                seen_files.add(resolved)
                try:
                    sample = file_path.read_bytes()[:8192].decode("utf-8", errors="replace")
                except OSError as exc:
                    diagnostics.append({"file": str(file_path), "status": "read-error", "detail": str(exc)})
                    continue
                adapter = next((a for a in ADAPTERS if a.matches(file_path, sample)), None)
                if adapter is None:
                    diagnostics.append({"file": str(file_path), "status": "unsupported", "detail": ""})
                    continue
                count_before = len(events)
                try:
                    events.extend(adapter.parse(file_path))
                    diagnostics.append({
                        "file": str(file_path), "status": "parsed",
                        "detail": f"{adapter.name}: {len(events)-count_before} events",
                    })
                except Exception as exc:
                    diagnostics.append({"file": str(file_path), "status": "parse-error", "detail": f"{adapter.name}: {exc}"})
        finally:
            if temp is not None:
                temp.cleanup()
    return events, diagnostics


def classify(event: Event) -> str:
    category = (event.category or "").strip()
    action = (event.action or "").lower()
    record_type = str(event.metadata.get("record_type", "")).lower()
    role = str(event.metadata.get("role", "")).lower()
    tool = (event.tool_name or "").lower()
    structured = " ".join((category.lower(), action, record_type, tool))

    if category == "Prompt":
        return "ENVIRONMENT CONTEXT" if event.text.lstrip().startswith("<environment_context>") else "USER PROMPT"
    if category == "AssistantMessage":
        return "ASSISTANT RESPONSE"
    if role == "developer":
        return "DEVELOPER INSTRUCTION"
    if role == "system":
        return "SYSTEM CONFIGURATION"
    if record_type == "session_meta":
        return "SESSION METADATA"
    if any(x in structured for x in ("approval", "request_permissions")):
        return "APPROVAL"
    if any(x in structured for x in ("apply_patch", "write_file", "edit_file", "file_write")):
        return "FILE CHANGE"
    if any(x in structured for x in ("read_file", "open_file", "view_file", "file_read")):
        return "FILE READ"
    if any(x in structured for x in ("exec_command", "shell_command", "commandevent", "powershell", "cmd.exe")):
        return "COMMAND"
    if "git" in tool or action.startswith("git"):
        return "GIT"
    if "mcp" in structured:
        return "MCP"
    if any(x in structured for x in ("plugin", "skill")):
        return "PLUGIN / SKILL"
    if any(x in structured for x in ("network", "http", "sse", "websocket", "dns")):
        return "NETWORK / API"
    if event.model or any(x in structured for x in ("token_usage", "input_tokens", "output_tokens")):
        return "MODEL / TOKEN"
    if event.level.lower() in {"error", "warn", "warning", "fatal"}:
        return "WARNING / ERROR"
    if category == "ExternalTelemetry":
        return "EXTERNAL TELEMETRY"
    if event.tool_name or category == "ToolOrAction":
        return "TOOL"
    if category == "SessionOrTurn":
        return "SESSION"
    return "RUNTIME"


def event_session_key(event: Event) -> str:
    if event.session_id:
        return f"{event.agent}:session:{event.session_id}"
    if event.turn_id:
        return f"{event.agent}:turn:{event.turn_id}"
    if event.process_id:
        return f"{event.agent}:process:{event.process_id}"
    if event.source_file:
        return f"{event.agent}:file:{Path(event.source_file).name}"
    return f"{event.agent}:uncorrelated:{event.username or 'unknown'}"


def deduplicate(events: list[Event], window_seconds: float = 2.0) -> list[Event]:
    ordered = sorted(events, key=lambda e: (
        parse_timestamp(e.timestamp_utc) or dt.datetime.max.replace(tzinfo=dt.timezone.utc),
        e.source_file, e.source_line,
    ))
    output: list[Event] = []
    fingerprints: dict[str, dt.datetime | None] = {}
    for event in ordered:
        normalized = re.sub(r"\s+", " ", event.text or event.details).strip().lower()
        fp = hash_text("|".join([event.agent, event.category, event.action, normalized[:4000], event.session_id, event.call_id]))
        ts = parse_timestamp(event.timestamp_utc)
        prior = fingerprints.get(fp)
        if prior is not None and ts is not None and abs((ts - prior).total_seconds()) <= window_seconds:
            continue
        if fp in fingerprints and prior is None and ts is None:
            continue
        fingerprints[fp] = ts
        output.append(event)
    return output



def strip_markup_and_urls(text: str) -> str:
    """Remove URL strings and markup while retaining explicit <path> values."""
    value = IOC_PATTERNS["url"].sub(" ", text)
    value = re.sub(r"<(?!/?path\b)[^>]+>", " ", value, flags=re.I)
    return value


def normalize_path_candidate(value: str) -> str:
    value = value.strip().strip("'\"`")
    value = re.sub(r"</?path\s*>", "", value, flags=re.I).strip()
    value = value.replace("\\\\", "\\")
    # Remove punctuation produced by prose, JSON, or protocol wrappers.
    value = re.sub(r"[\s}\]>)>,;:'\"`]+$", "", value)
    value = re.sub(r"[.]+$", "", value)
    return value.strip()


def is_valid_filesystem_path(value: str) -> bool:
    if not value or "<" in value or ">" in value:
        return False

    lower = value.lower()
    if "://" in lower:
        return False
    if lower.startswith(("/chatgpt.com/", "/backend-api/", "/api/", "/v1/", "/v2/")):
        return False
    if any(token in lower for token in (
        "jsonrpc", "otel.name", "submission_id=", "thread_id=", "codex.op="
    )):
        return False

    if re.match(r"^[A-Za-z]:\\", value):
        if value.count("\\") < 2 or len(value) <= 4:
            return False
        if re.match(r"^[A-Za-z]:\\[nrt]$", value, re.I):
            return False
        if not re.match(r"^[A-Za-z]:\\[^<>|*?\"\r\n]+$", value):
            return False
        return True

    if value.startswith("/"):
        allowed_roots = (
            "/home/", "/users/", "/tmp/", "/var/", "/etc/", "/opt/",
            "/usr/", "/workspace/", "/workspaces/", "/mnt/", "/srv/",
            "/root/", "/private/",
        )
        if not lower.startswith(allowed_roots):
            return False
        parts = [p for p in value.split("/") if p]
        if len(parts) < 2:
            return False
        if any(part.lower() in {
            "path", "entry", "special", "filesystem", "permission_profile"
        } for part in parts):
            return False
        return True

    return False


def extract_filesystem_paths(
    text: str,
    structured_values: Optional[Iterable[str]] = None,
    allow_free_text: bool = True,
) -> list[str]:
    """
    Extract only high-confidence filesystem paths.

    Structured values such as cwd/target are trusted first. Free-text extraction
    is reserved for meaningful prompt/tool/file events and is not performed on
    arbitrary runtime telemetry.
    """
    candidates: list[str] = []

    for value in structured_values or []:
        if value:
            candidates.append(str(value))

    # Exact values within Codex permission-profile/path elements.
    candidates.extend(
        match.group(1)
        for match in re.finditer(r"<path>\s*(.*?)\s*</path>", text, flags=re.I | re.S)
    )

    if allow_free_text:
        cleaned = strip_markup_and_urls(text)

        # Windows paths bounded by whitespace, quotes, or markup.
        win_pattern = re.compile(
            r"(?<![A-Za-z0-9_])([A-Za-z]:\\"
            r"(?:[^\\/:*?\"<>|\r\n\s]+\\)+"
            r"[^\\/:*?\"<>|\r\n\s,;}\])>]*)"
        )
        candidates.extend(match.group(1) for match in win_pattern.finditer(cleaned))

        # Restrict POSIX extraction to real filesystem roots.
        posix_pattern = re.compile(
            r"(?<![A-Za-z0-9_])"
            r"((?:/home|/Users|/tmp|/var|/etc|/opt|/usr|/workspace|/workspaces|/mnt|/srv|/root|/private)"
            r"(?:/[^/\s<>\"'`,;}\])>]+)+)"
        )
        candidates.extend(match.group(1) for match in posix_pattern.finditer(cleaned))

    output: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        value = normalize_path_candidate(candidate)
        if not is_valid_filesystem_path(value):
            continue
        key = value.lower() if re.match(r"^[A-Za-z]:\\", value) else value
        if key in seen:
            continue
        seen.add(key)
        output.append(value)
    return output


def categorize_path(path: str) -> str:
    lower = path.lower().replace("/", "\\")
    if "\\sessions\\" in lower or lower.endswith(".jsonl"):
        return "Session Files"
    if "\\visualizations\\" in lower:
        return "Visualization Paths"
    if "\\.git" in lower or lower.endswith("\\.git"):
        return "Git Paths"
    if "\\.codex" in lower or "\\.claude" in lower or "\\.gemini" in lower or "\\.continue" in lower:
        return "Agent Config / State"
    if "\\.cargo\\registry\\" in lower or "\\cargo\\registry\\" in lower or "/.cargo/registry/" in path.lower() or "/cargo/registry/" in path.lower():
        return "Runtime Libraries"
    if any(lower.endswith(ext) for ext in (
        ".py", ".ps1", ".js", ".ts", ".tsx", ".jsx", ".java", ".cs", ".go",
        ".rs", ".cpp", ".c", ".h", ".hpp", ".rb", ".php", ".sh", ".yml",
        ".yaml", ".json", ".toml", ".xml", ".html", ".css", ".sql",
    )):
        return "Source / Project Files"
    if "\\documents\\codex" in lower or "/projects/" in path.lower() or "/workspace/" in path.lower():
        return "Workspace Paths"
    if "\\temp\\" in lower or "\\tmp\\" in lower or path.startswith("/tmp/"):
        return "Temporary Files"
    return "Other Filesystem Paths"


def path_interest_score(path: str, category: str) -> int:
    scores = {
        "Workspace Paths": 5,
        "Source / Project Files": 5,
        "Git Paths": 4,
        "Session Files": 3,
        "Agent Config / State": 3,
        "Visualization Paths": 2,
        "Temporary Files": 1,
        "Runtime Libraries": 1,
        "Other Filesystem Paths": 2,
    }
    score = scores.get(category, 1)
    lower = path.lower()
    if any(token in lower for token in ("\\runneradmin\\", "/usr/lib/", "/site-packages/", "\\cargo\\registry\\")):
        score = min(score, 1)
    return score


def infer_project_root(path: str) -> str:
    """Infer a useful project root rather than counting every child path."""
    normalized = path.replace("/", "\\")
    lower = normalized.lower()

    # Remove known internal suffixes first.
    for marker in ("\\.git", "\\.agents", "\\.codex", "\\.claude", "\\.gemini"):
        idx = lower.find(marker)
        if idx > 2:
            normalized = normalized[:idx]
            lower = normalized.lower()

    # Prefer common workspace anchors.
    anchors = ("\\documents\\codex\\", "\\projects\\", "\\workspace\\", "\\src\\")
    for anchor in anchors:
        idx = lower.find(anchor)
        if idx >= 0:
            prefix = normalized[: idx + len(anchor)]
            remainder = normalized[idx + len(anchor):]
            parts = [p for p in remainder.split("\\") if p]
            if parts:
                # Keep up to two components after the anchor to identify the project.
                return prefix + "\\".join(parts[:2])

    # For session/config/runtime paths, do not call them projects.
    category = categorize_path(path)
    if category in {"Session Files", "Visualization Paths", "Agent Config / State", "Runtime Libraries", "Temporary Files"}:
        return ""

    parts = [p for p in normalized.split("\\") if p]
    if re.match(r"^[A-Za-z]:$", parts[0] if parts else "") and len(parts) >= 4:
        return "\\".join(parts[:4])
    if path.startswith("/") and len(parts) >= 3:
        return "/" + "/".join(parts[:3])
    return ""


def extract_urls_domains_endpoints(text: str) -> tuple[list[str], list[str], list[str]]:
    urls, domains, endpoints = [], [], []
    seen_urls, seen_domains, seen_endpoints = set(), set(), set()
    for match in IOC_PATTERNS["url"].finditer(text):
        url = normalize_url(match.group(0))
        try:
            parsed = urlparse(url)
        except ValueError:
            continue
        if not parsed.scheme or not parsed.hostname:
            continue
        if url not in seen_urls:
            seen_urls.add(url); urls.append(url)
        host = parsed.hostname.lower()
        if valid_domain(host) and host not in seen_domains:
            seen_domains.add(host); domains.append(host)
        if parsed.path and parsed.path != "/":
            endpoint = parsed.path + (("?" + parsed.query) if parsed.query else "")
            endpoint = endpoint.rstrip("`'\".,;:")
            if endpoint and endpoint not in seen_endpoints:
                seen_endpoints.add(endpoint); endpoints.append(endpoint)
    return urls, domains, endpoints


def enrich_event(event: Event) -> dict[str, Any]:
    if not event.agent or event.agent == "generic":
        event.agent = "codex"
    etype = classify(event)
    combined = event.searchable_text()
    free_text_path_types = {
        "USER PROMPT", "COMMAND", "FILE READ", "FILE CHANGE", "GIT",
        "TOOL", "MCP", "PLUGIN / SKILL",
    }
    structured_path_values = [
        event.working_directory,
        event.target if is_valid_filesystem_path(normalize_path_candidate(event.target)) else "",
    ]
    paths = extract_filesystem_paths(
        combined,
        structured_values=structured_path_values,
        allow_free_text=etype in free_text_path_types,
    )[:100]
    urls, domains, api_endpoints = extract_urls_domains_endpoints(combined)
    path_observation = (
        "declared"
        if etype in {"ENVIRONMENT CONTEXT", "SYSTEM CONFIGURATION", "DEVELOPER INSTRUCTION", "SESSION METADATA"}
        else "observed"
    )
    path_records = [
        {
            "path": path,
            "category": categorize_path(path),
            "interest_score": path_interest_score(path, categorize_path(path)),
            "project_root": infer_project_root(path),
            "observation": path_observation,
        }
        for path in paths
    ]
    commands = extract_structured_commands(event)
    git_ops = [m.group(1).lower() for m in GIT_PATTERN.finditer(combined)]
    model = clean_model_id(event.model) or clean_model_id(
        first_value(event.metadata, ["model_name", "model_id"])
    )
    input_tokens = first_value(event.metadata, ["input_tokens", "prompt_tokens"])
    output_tokens = first_value(event.metadata, ["output_tokens", "completion_tokens"])
    reasoning = first_value(event.metadata, ["reasoning_effort", "reasoning"])
    secrets = []
    for name, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(combined):
            value = match.group(0)
            secrets.append({"type": name, "masked": mask_secret(value), "source": "event"})
    summary_source = event.text or event.details or event.target or event.action or etype
    summary = re.sub(r"\s+", " ", summary_source).strip()
    if len(summary) > 300:
        summary = summary[:300] + "…"
    return {
        **asdict(event),
        "event_type": etype,
        "session_key": event_session_key(event),
        "correlation_key": event.call_id or event.turn_id or event.session_id or event.process_id,
        "summary": summary,
        "paths": paths,
        "path_records": path_records,
        "urls": urls,
        "domains": domains,
        "api_endpoints": api_endpoints,
        "commands": commands[:30],
        "git_operations": git_ops,
        "model_detected": model,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "reasoning": reasoning,
        "secret_findings": secrets,
    }


def redact_secrets(value: str) -> tuple[str, list[dict[str, str]]]:
    findings: list[dict[str, str]] = []
    redacted = value
    for name, pattern in SECRET_PATTERNS.items():
        def replace(match: re.Match[str]) -> str:
            original = match.group(0)
            findings.append({"type": name, "masked": mask_secret(original), "sha256": hash_text(original)})
            return mask_secret(original)
        redacted = pattern.sub(replace, redacted)
    return redacted, findings


def redact_event_for_output(event: dict[str, Any]) -> dict[str, Any]:
    item = dict(event)
    findings: list[dict[str, str]] = []
    for field in ("text", "details", "summary", "target", "working_directory"):
        item[field], found = redact_secrets(str(item.get(field, "") or ""))
        findings.extend(found)
    for field in ("commands", "urls", "api_endpoints"):
        values = item.get(field, [])
        if isinstance(values, list):
            cleaned = []
            for value in values:
                safe, found = redact_secrets(str(value))
                cleaned.append(safe)
                findings.extend(found)
            item[field] = cleaned
    if findings:
        item["secret_findings"] = list(item.get("secret_findings", [])) + findings
    return item


MODEL_ID_PATTERN = re.compile(r"^(?:gpt|o[1-9]|codex|claude|gemini)[A-Za-z0-9._-]*$", re.I)
COMMON_FILE_EXTENSIONS = {
    "md", "json", "yaml", "yml", "toml", "py", "js", "ts", "tsx", "jsx",
    "html", "css", "xml", "csv", "txt", "log", "rs", "go", "java", "cs",
}


def clean_model_id(value: Any) -> str:
    candidate = str(value or "").strip().strip("'\"")
    return candidate if len(candidate) <= 120 and MODEL_ID_PATTERN.fullmatch(candidate) else ""


def extract_structured_commands(event: Event) -> list[str]:
    structured = " ".join((event.category.lower(), event.action.lower(), event.tool_name.lower()))
    if not any(x in structured for x in (
        "exec_command", "shell_command", "commandevent", "powershell",
        "cmd.exe", "bash", "zsh", "shell",
    )):
        return []
    values: list[str] = []
    for key in ("command", "cmd", "argv", "process_command_line"):
        value = first_value(event.metadata, [key])
        if isinstance(value, list):
            values.append(" ".join(str(x) for x in value))
        elif value:
            values.append(str(value))
    if not values:
        values = [x.strip() for x in (event.text + "\n" + event.details).splitlines() if x.strip()]
    return list(dict.fromkeys(re.sub(r"\s+", " ", x).strip() for x in values if x.strip()))[:30]


def valid_domain(value: str) -> bool:
    value = value.strip().strip("`'\".,;:()[]{}<>").lower()
    if value == "localhost" or "." not in value or len(value) > 253:
        return False
    labels = value.split(".")
    if labels[-1] in COMMON_FILE_EXTENSIONS:
        return False
    return all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels)


def normalize_url(value: str) -> str:
    value = value.strip().strip("`'\"")
    return re.sub(r"[)\]}>.,;:]+$", "", value)


def mask_secret(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


NETWORK_REQUEST_URL = re.compile(
    r"""(?ix)
    (?:
        \b(?:request[_ .-]?url|url|uri|endpoint)\s*[:=]\s*["']?
        |
        \b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+
    )
    (https?://[^\s<>'"\]\)]+)
    """
)
NETWORK_TOOL_MARKERS = (
    "browser", "curl", "dns", "fetch", "http", "invoke-restmethod",
    "invoke-webrequest", "nslookup", "open_url", "search_query", "web.run",
    "web_request", "websocket", "wget",
)
NETWORK_COMMAND = re.compile(
    r"(?i)\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|nslookup|dig)\b"
)
DNS_QUERY = re.compile(
    r"(?i)\b(?:nslookup|dig)\s+(?:-[A-Za-z0-9-]+\s+)*"
    r"([A-Za-z0-9](?:[A-Za-z0-9.-]{1,251}[A-Za-z0-9]))"
)
HTTP_REQUEST_CONTEXT = re.compile(
    r"(?i)\b(?:http\.method|method)\s*[:=]\s*"
    r"(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b"
)
CODEX_SHELL_COMMAND = re.compile(
    r"""(?x)
    tools\.shell_command\(\s*\{\s*
    ["']command["']\s*:\s*
    ("(?:\\.|[^"\\])*")
    """
)


def valid_network_host(value: str) -> str:
    candidate = value.strip().strip("[](){}<>`'\".,;:").lower()
    if not candidate:
        return ""
    try:
        ip = ipaddress.ip_address(candidate)
        if ip.is_loopback or ip.is_unspecified:
            return ""
        return str(ip)
    except ValueError:
        return candidate if valid_domain(candidate) else ""


def network_observables(event: dict[str, Any]) -> list[tuple[str, str]]:
    """
    Extract only contacted/requested network targets.

    Arbitrary URLs and domains in prompts, documentation, source code, model
    responses, and tool output are intentionally excluded.
    """
    text_fields = "\n".join(
        str(event.get(key, "") or "")
        for key in ("text", "details", "target")
    )
    structured = " ".join(
        str(event.get(key, "") or "").lower()
        for key in ("event_type", "category", "action", "tool_name")
    )
    metadata = event.get("metadata", {})
    values: list[tuple[str, str]] = []

    # Explicit HTTP request targets such as method=GET url=https://...
    has_request_context = (
        str(event.get("event_type", "")).upper() == "NETWORK / API"
        or HTTP_REQUEST_CONTEXT.search(text_fields) is not None
        or any(marker in structured for marker in NETWORK_TOOL_MARKERS)
        or (
            str(event.get("source_type", "")).lower().startswith("sqlite:")
            and NETWORK_REQUEST_URL.search(text_fields) is not None
        )
    )
    if has_request_context:
        for match in NETWORK_REQUEST_URL.finditer(text_fields):
            values.append(("url", match.group(1).rstrip(".,;:")))

    # Structured destination fields from imported EDR/SIEM or agent records.
    for key in (
        "request_url", "request_uri", "url", "uri", "endpoint",
        "destination_url", "remote_url",
    ):
        candidate = first_value(metadata, [key])
        if candidate:
            candidate_text = str(candidate)
            if IOC_PATTERNS["url"].fullmatch(candidate_text.rstrip(".,;:")):
                values.append(("url", candidate_text.rstrip(".,;:")))

    for key in (
        "destinationhostname", "destination_host", "remote_host", "remote_hostname",
        "server_name", "dns_query", "query_name",
    ):
        candidate = first_value(metadata, [key])
        if candidate:
            host = valid_network_host(str(candidate))
            if host:
                values.append(("ipv4" if re.fullmatch(r"\d+(?:\.\d+){3}", host) else "domain", host))

    # Explicit network tools represent an action; their URL arguments are
    # targets. Tool outputs generally lack the originating network tool name.
    if any(marker in structured for marker in NETWORK_TOOL_MARKERS):
        for url in IOC_PATTERNS["url"].findall(text_fields):
            values.append(("url", url.rstrip(".,;:")))

    # Network commands are evaluated from structured command fields or decoded
    # shell-command arguments, never from arbitrary tool output/source text.
    command_values = [str(value) for value in event.get("commands", []) if str(value).strip()]
    if str(event.get("event_type", "")).upper() == "COMMAND":
        command_values.append(text_fields)
    if str(event.get("tool_name", "")).lower() == "exec":
        for match in CODEX_SHELL_COMMAND.finditer(text_fields):
            try:
                command_values.append(json.loads(match.group(1)))
            except (ValueError, TypeError):
                continue

    for command in command_values:
        for line in command.splitlines():
            if not NETWORK_COMMAND.search(line):
                continue
            for url in IOC_PATTERNS["url"].findall(line):
                values.append(("url", url.rstrip(".,;:")))
            for match in DNS_QUERY.finditer(line):
                host = valid_network_host(match.group(1))
                if host:
                    values.append(("ipv4" if re.fullmatch(r"\d+(?:\.\d+){3}", host) else "domain", host))

    # Derive destination domains from confirmed request URLs.
    expanded: list[tuple[str, str]] = []
    for kind, value in values:
        if kind == "url":
            try:
                host = urlparse(value).hostname
            except ValueError:
                host = None
            normalized = valid_network_host(host or "")
            if not normalized:
                continue
            expanded.append((kind, value))
            host_kind = "ipv4" if re.fullmatch(r"\d+(?:\.\d+){3}", normalized) else "domain"
            expanded.append((host_kind, normalized))
        else:
            expanded.append((kind, value))

    return list(dict.fromkeys(expanded))


def extract_iocs(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    found: dict[tuple[str, str], dict[str, Any]] = {}
    for event in events:
        text = "\n".join(str(event.get(k, "")) for k in ("text", "details", "target", "working_directory"))
        for kind, pattern in IOC_PATTERNS.items():
            if kind in {"url", "domain", "ipv4"}:
                continue
            for match in pattern.finditer(text):
                value = match.group(1) if kind == "gcp_project" and match.groups() else match.group(0)
                value = value.rstrip(".,;:")
                key = (kind, value.lower())
                item = found.setdefault(key, {
                    "type": kind, "value": value, "first_seen": event.get("timestamp_utc", ""),
                    "last_seen": event.get("timestamp_utc", ""), "count": 0,
                    "agents": set(), "source_events": [],
                })
                item["count"] += 1
                item["last_seen"] = event.get("timestamp_utc", "") or item["last_seen"]
                item["agents"].add(event.get("agent", ""))
                if len(item["source_events"]) < 20:
                    item["source_events"].append(event.get("event_number", ""))
        for kind, value in network_observables(event):
            key = (kind, value.lower())
            item = found.setdefault(key, {
                "type": kind, "value": value, "first_seen": event.get("timestamp_utc", ""),
                "last_seen": event.get("timestamp_utc", ""), "count": 0,
                "agents": set(), "source_events": [],
            })
            item["count"] += 1
            item["last_seen"] = event.get("timestamp_utc", "") or item["last_seen"]
            item["agents"].add(event.get("agent", ""))
            if len(item["source_events"]) < 20:
                item["source_events"].append(event.get("event_number", ""))
    result = []
    for item in found.values():
        item["agents"] = sorted(x for x in item["agents"] if x)
        result.append(item)
    return sorted(result, key=lambda x: (x["type"], x["value"].lower()))


def import_external_csv(path: Path) -> list[Event]:
    events: list[Event] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for idx, row in enumerate(reader, 2):
            lower = {str(k).lower(): v for k, v in row.items()}
            timestamp = next((lower.get(k, "") for k in ("timestamputc", "timestamp", "time", "datetime", "@timestamp") if lower.get(k)), "")
            message = next((lower.get(k, "") for k in ("message", "details", "event", "commandline", "process_command_line") if lower.get(k)), "")
            category = next((lower.get(k, "") for k in ("category", "event_type", "eventtype", "source") if lower.get(k)), "ExternalTelemetry")
            events.append(Event(
                timestamp_utc=iso_utc(timestamp), agent="external", category="ExternalTelemetry",
                action=str(category), text=str(message), details=json.dumps(row, ensure_ascii=False),
                username=str(lower.get("username", lower.get("user", ""))),
                hostname=str(lower.get("hostname", lower.get("computer", lower.get("device_name", "")))),
                process_id=str(lower.get("process_id", lower.get("pid", ""))),
                source_type="external_csv", source_file=str(path), source_line=str(idx),
                evidence_hash=hash_text(json.dumps(row, sort_keys=True, default=str)),
                metadata=row,
            ))
    return events


def add_event_numbers(events: list[dict[str, Any]]) -> None:
    events.sort(key=lambda e: (
        parse_timestamp(str(e.get("timestamp_utc", ""))) or dt.datetime.max.replace(tzinfo=dt.timezone.utc),
        str(e.get("source_file", "")), str(e.get("source_line", "")),
    ))
    previous: dict[str, dt.datetime] = {}
    for idx, event in enumerate(events, 1):
        event["event_number"] = idx
        ts = parse_timestamp(str(event.get("timestamp_utc", "")))
        key = str(event.get("session_key", ""))
        event["delta_seconds"] = ""
        if ts and key in previous:
            event["delta_seconds"] = round((ts - previous[key]).total_seconds(), 3)
        if ts:
            previous[key] = ts


def is_clean_assistant_response(message: str, event: dict[str, Any]) -> bool:
    """
    Return True when an assistant record looks like user-facing natural language
    rather than Codex runtime, telemetry, protocol, or tool-initialization output.
    """
    value = message.strip()
    if not value:
        return False

    lower = value.lower()
    action = str(event.get("action", "")).lower()
    source_type = str(event.get("source_type", "")).lower()

    runtime_markers = (
        "start_server_task",
        "session_loop[",
        "submission_dispatch(",
        "jsonrpc",
        "jsonrpcresponse",
        "peermessage(",
        "listtoolsresult",
        "listtoolresult",
        "otel.name",
        "codex.op=",
        "thread_id=",
        "submission_id=",
        "mcp_server",
        "initialize:serve_inner",
        "response(jsonrpc",
        "toolresult",
        "toolcall",
        "function_call",
        "functioncall",
    )
    if any(marker in lower for marker in runtime_markers):
        return False

    # Protocol/object dumps tend to have many structural tokens and very little
    # ordinary prose. This catches changed runtime strings without depending
    # entirely on exact marker names.
    structural_tokens = sum(lower.count(token) for token in (
        "{", "}", "[", "]", "::", "=", "(", ")", "jsonrpc", "result:",
    ))
    words = re.findall(r"[A-Za-z][A-Za-z'-]*", value)
    sentences = re.findall(r"[.!?](?:\s|$)", value)

    if structural_tokens >= 10 and len(sentences) == 0:
        return False
    if structural_tokens >= 16 and len(words) < 40:
        return False

    # Reject records whose own metadata says they are runtime/tool events even
    # if an upstream parser labeled them as AssistantMessage.
    if any(token in action for token in ("runtime", "tool", "sessionevent", "sqlite")):
        if structural_tokens >= 5 or any(marker in lower for marker in runtime_markers):
            return False

    # Human-facing responses normally contain prose. Permit short acknowledgments
    # but reject identifier-heavy single-line records.
    identifier_chunks = re.findall(r"[A-Za-z_][A-Za-z0-9_.:-]{12,}", value)
    if len(words) < 5 and len(identifier_chunks) >= 2:
        return False

    return True


MOJIBAKE_MARKERS = ("Ã", "Â", "â€", "â€™", "â€œ", "â€", "â€“", "â—")


def decode_escaped_text(value: str) -> str:
    """Decode safe text escapes left by nested JSON serialization."""
    if not value:
        return value

    for escaped, actual in (
        ("\\r\\n", "\n"),
        ("\\n", "\n"),
        ("\\r", "\n"),
        ("\\t", "\t"),
        ('\\"', '"'),
        ("\\'", "'"),
    ):
        value = value.replace(escaped, actual)

    def decode_unicode(match: re.Match[str]) -> str:
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    return re.sub(r"\\u([0-9a-fA-F]{4})", decode_unicode, value)


def repair_mojibake(value: str) -> str:
    """Repair common UTF-8 bytes decoded as CP-1252 or Latin-1."""
    if not value or not any(marker in value for marker in MOJIBAKE_MARKERS):
        return value

    candidates = [value]
    for encoding in ("cp1252", "latin-1"):
        try:
            candidates.append(value.encode(encoding).decode("utf-8"))
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass

    def score(candidate: str) -> tuple[int, int]:
        return (
            sum(candidate.count(marker) for marker in MOJIBAKE_MARKERS),
            candidate.count("\ufffd"),
        )

    return min(candidates, key=score)


def normalize_replay_message(value: str) -> str:
    """Normalize replay text without damaging Windows paths."""
    value = html.unescape(str(value or ""))
    value = decode_escaped_text(value)
    value = repair_mojibake(value)
    value = re.sub(
        r"^\s*(?:input_text|output_text)\s*(?:\r?\n)?",
        "",
        value,
        flags=re.I,
    )
    value = value.replace("\x00", "")
    value = value.replace("\u2028", "\n").replace("\u2029", "\n")
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    value = re.sub(r"[ \t]+\n", "\n", value)
    value = re.sub(r"\n[ \t]+", "\n", value)
    value = re.sub(r"\n{3,}", "\n\n", value)
    return value.strip()


def replay_fingerprint(role: str, message: str) -> str:
    """Create a stable fingerprint across encoding, formatting, and escape-depth variants."""
    normalized = normalize_replay_message(message).lower()
    normalized = normalized.translate(str.maketrans({
        "’": "'", "‘": "'", "“": '"', "”": '"', "–": "-", "—": "-",
    }))

    # Nested JSON/SQLite serialization can preserve a different number of
    # backslashes for the same CSS/Unicode escape:
    #   "\\2315" and "\2315"
    # Canonicalize only for comparison. Display text remains unchanged.
    normalized = re.sub(
        r"\\+(?=[0-9a-f]{1,6}(?:\s|[\"'`;,.)\]}]|$))",
        r"\\",
        normalized,
        flags=re.I,
    )

    # Normalize differences such as \"text\" versus "text".
    normalized = re.sub(r"\\+([\"'])", r"\1", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    normalized = re.sub(r"[`\"']", "", normalized)
    return f"{role}:{normalized}"


def messages_near_duplicate(left: str, right: str) -> bool:
    """Match replay copies with minor escape or serialization differences."""
    a = replay_fingerprint("", left).split(":", 1)[-1]
    b = replay_fingerprint("", right).split(":", 1)[-1]
    if a == b:
        return True
    if not a or not b:
        return False

    # Additional conservative fold for hexadecimal CSS escapes.
    slash_fold_a = re.sub(r"\\+(?=[0-9a-f]{1,6}\b)", r"\\", a, flags=re.I)
    slash_fold_b = re.sub(r"\\+(?=[0-9a-f]{1,6}\b)", r"\\", b, flags=re.I)
    if slash_fold_a == slash_fold_b:
        return True

    shorter, longer = sorted((a, b), key=len)
    if len(shorter) >= 20 and longer.startswith(shorter):
        remainder = longer[len(shorter):].strip()
        if remainder in {"n", "\\n", '"n', "'n"} or len(remainder) <= 3:
            return True
    return False


def build_replay(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Create a clean conversation replay from explicitly role-tagged raw
    conversation records emitted by dedicated app adapters.

    Unstructured SQLite and generic runtime records remain in Timeline, but are
    excluded from Replay because source code can resemble serialized messages.
    """
    conversation_types = {"USER PROMPT", "ASSISTANT RESPONSE"}
    candidates = []
    for event in events:
        if event.get("event_type", "") not in conversation_types:
            continue

        metadata = event.get("metadata", {})
        if not isinstance(metadata, dict):
            continue

        source_type = str(event.get("source_type", "")).lower()
        role = str(metadata.get("role", "")).lower()
        eligible = bool(metadata.get("conversation_eligible"))

        # Case Replay is intentionally stricter than Timeline. Only raw,
        # explicitly role-tagged messages from a dedicated app adapter enter.
        authoritative_sources = {
            "codex_session_jsonl",
            "gemini_antigravity_jsonl",
        }
        if source_type not in authoritative_sources:
            continue
        if not eligible:
            continue
        if role not in {"user", "human", "assistant", "ai"}:
            continue

        candidates.append(event)

    def source_priority(event: dict[str, Any]) -> int:
        source_type = str(event.get("source_type", "")).lower()
        source_file = str(event.get("source_file", "")).lower()
        if "session_jsonl" in source_type or source_file.endswith((".jsonl", ".ndjson")):
            return 0
        if source_type.startswith("sqlite:") or source_file.endswith((".sqlite", ".sqlite3", ".db")):
            return 1
        return 2

    selected = sorted(
        candidates,
        key=lambda event: (
            parse_timestamp(str(event.get("timestamp_utc", "")))
            or dt.datetime.max.replace(tzinfo=dt.timezone.utc),
            source_priority(event),
        ),
    )

    replay: list[dict[str, Any]] = []
    exact_seen: set[str] = set()

    for event in selected:
        event_type = str(event.get("event_type", ""))
        raw_message = str(event.get("text", "") or event.get("summary", "")).strip()
        message = normalize_replay_message(raw_message)
        if not message:
            continue

        stripped = message.lstrip()
        if (
            stripped.startswith("<environment_context>")
            or stripped.startswith("<recommended_plugins>")
            or stripped.startswith("<permissions")
            or stripped.startswith("<workspace")
        ):
            continue

        if event_type == "ASSISTANT RESPONSE" and not is_clean_assistant_response(message, event):
            continue

        source_role = str(event.get("metadata", {}).get("role", "")).lower()
        role = "user" if source_role in {"user", "human"} else "agent"
        fingerprint = replay_fingerprint(role, message)
        if fingerprint in exact_seen:
            continue

        timestamp = parse_timestamp(str(event.get("timestamp_utc", "")))
        duplicate = False
        for previous in reversed(replay[-8:]):
            if previous["role"] != role:
                continue

            previous_timestamp = parse_timestamp(str(previous.get("timestamp_utc", "")))
            if timestamp and previous_timestamp:
                delta = abs((timestamp - previous_timestamp).total_seconds())
                if delta > 15:
                    break

            if messages_near_duplicate(previous["message"], message):
                duplicate = True
                break

        if duplicate:
            continue

        exact_seen.add(fingerprint)

        replay.append({
            "timestamp_utc": event.get("timestamp_utc", ""),
            "event_number": event.get("event_number", ""),
            "session_key": event.get("session_key", ""),
            "agent": str(event.get("agent", "") or "unknown"),
            "role": role,
            "event_type": event_type,
            "message": message,
        })

    return replay


def analytics(events: list[dict[str, Any]], iocs: list[dict[str, Any]]) -> dict[str, Any]:
    by_type = Counter(e["event_type"] for e in events)
    by_agent = Counter(e["agent"] for e in events)
    models = Counter(str(e.get("model_detected", "")) for e in events if e.get("model_detected"))
    tools = Counter(str(e.get("tool_name", "")) for e in events if e.get("tool_name"))
    directories = Counter(str(e.get("working_directory", "")) for e in events if e.get("working_directory"))
    git_ops = Counter(op for e in events for op in e.get("git_operations", []))
    secret_counts = Counter(s["type"] for e in events for s in e.get("secret_findings", []))

    path_counts = Counter()
    declared_path_counts = Counter()
    path_categories: dict[str, Counter] = defaultdict(Counter)
    project_counts = Counter()
    project_details: dict[str, dict[str, Any]] = {}
    scored_paths: dict[str, dict[str, Any]] = {}

    for event in events:
        for record in event.get("path_records", []):
            path = record["path"]
            category = record["category"]
            score = int(record["interest_score"])
            root = record.get("project_root", "")
            if record.get("observation", "observed") == "declared":
                declared_path_counts[path] += 1
                continue
            path_counts[path] += 1
            path_categories[category][path] += 1
            current = scored_paths.setdefault(path, {
                "path": path, "category": category, "interest_score": score, "count": 0
            })
            current["count"] += 1
            current["interest_score"] = max(current["interest_score"], score)

            if root:
                project_counts[root] += 1
                detail = project_details.setdefault(root, {
                    "project_root": root,
                    "references": 0,
                    "categories": Counter(),
                    "paths": set(),
                    "has_git": False,
                    "has_agent_workspace": False,
                    "has_visualizations": False,
                })
                detail["references"] += 1
                detail["categories"][category] += 1
                detail["paths"].add(path)
                lower = path.lower()
                detail["has_git"] = detail["has_git"] or ".git" in lower
                detail["has_agent_workspace"] = detail["has_agent_workspace"] or any(
                    token in lower for token in (".agents", ".codex", ".claude", ".gemini")
                )
                detail["has_visualizations"] = detail["has_visualizations"] or "visualizations" in lower

    interesting_paths = sorted(
        scored_paths.values(),
        key=lambda x: (-x["interest_score"], -x["count"], x["path"].lower()),
    )[:100]

    categorized_paths = {
        category: dict(counter.most_common(50))
        for category, counter in sorted(path_categories.items())
    }

    projects = []
    for root, detail in sorted(project_details.items(), key=lambda kv: (-kv[1]["references"], kv[0].lower())):
        projects.append({
            "project_root": root,
            "references": detail["references"],
            "unique_paths": len(detail["paths"]),
            "categories": dict(detail["categories"]),
            "has_git": detail["has_git"],
            "has_agent_workspace": detail["has_agent_workspace"],
            "has_visualizations": detail["has_visualizations"],
        })

    urls = Counter(url for e in events for url in e.get("urls", []))
    domains = Counter(domain for e in events for domain in e.get("domains", []))
    api_endpoints = Counter(endpoint for e in events for endpoint in e.get("api_endpoints", []))

    token_in = 0
    token_out = 0
    cumulative_usage: dict[str, dict[str, int]] = {}
    for event in events:
        raw_input = str(event.get("input_tokens", "") or "")
        raw_output = str(event.get("output_tokens", "") or "")
        input_count = int(raw_input) if raw_input.isdigit() else 0
        output_count = int(raw_output) if raw_output.isdigit() else 0
        if event.get("metadata", {}).get("token_usage_kind") == "cumulative":
            usage_key = str(event.get("source_file") or event.get("session_key") or "codex")
            current = cumulative_usage.setdefault(usage_key, {"input": 0, "output": 0})
            current["input"] = max(current["input"], input_count)
            current["output"] = max(current["output"], output_count)
        else:
            token_in += input_count
            token_out += output_count
    token_in += sum(item["input"] for item in cumulative_usage.values())
    token_out += sum(item["output"] for item in cumulative_usage.values())

    return {
        "total_events": len(events),
        "sessions": len({str(e.get("session_id", "")) for e in events if str(e.get("session_id", "")).strip()}),
        "turns": len({str(e.get("turn_id", "")) for e in events if str(e.get("turn_id", "")).strip()}),
        "processes": len({str(e.get("process_id", "")) for e in events if str(e.get("process_id", "")).strip()}),
        "uncorrelated_groups": len({
            e["session_key"] for e in events
            if not e.get("session_id") and not e.get("turn_id") and not e.get("process_id")
        }),
        "event_types": dict(by_type),
        "agents": dict(by_agent),
        "models": dict(models),
        "tools": dict(tools.most_common(30)),
        "working_directories": dict(directories.most_common(30)),
        "filesystem_paths": dict(path_counts.most_common(100)),
        "declared_paths": dict(declared_path_counts.most_common(100)),
        "interesting_paths": interesting_paths,
        "categorized_paths": categorized_paths,
        "user_projects": projects[:50],
        "urls": dict(urls.most_common(100)),
        "domains": dict(domains.most_common(100)),
        "api_endpoints": dict(api_endpoints.most_common(100)),
        "git_operations": dict(git_ops),
        "secret_findings": dict(secret_counts),
        "ioc_count": len(iocs),
        "token_usage": {"input": token_in, "output": token_out},
    }


def stix_pattern(ioc_type: str, value: str) -> Optional[str]:
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    mapping = {
        "domain": f"[domain-name:value = '{escaped}']",
        "ipv4": f"[ipv4-addr:value = '{escaped}']",
        "url": f"[url:value = '{escaped}']",
        "md5": f"[file:hashes.MD5 = '{escaped}']",
        "sha1": f"[file:hashes.'SHA-1' = '{escaped}']",
        "sha256": f"[file:hashes.'SHA-256' = '{escaped}']",
    }
    return mapping.get(ioc_type)


def write_stix(iocs: list[dict[str, Any]], path: Path) -> None:
    objects = []
    now = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    for item in iocs:
        pattern = stix_pattern(item["type"], item["value"])
        if not pattern:
            continue
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, item['type'] + ':' + item['value'])}",
            "created": now, "modified": now,
            "name": f"AI Agent DFIR extracted {item['type']}",
            "description": f"Extracted from local AI-agent forensic artifacts; observed {item['count']} time(s).",
            "indicator_types": ["malicious-activity"],
            "pattern": pattern, "pattern_type": "stix",
            "valid_from": now,
            "labels": ["ai-agent-dfir", "unvalidated"],
        })
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
    path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")


def write_csv(rows: list[dict[str, Any]], path: Path, fields: list[str]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            converted = {}
            for key in fields:
                value = row.get(key, "")
                if isinstance(value, (list, dict)):
                    value = json.dumps(value, ensure_ascii=False)
                converted[key] = value
            writer.writerow(converted)


def safe(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def render_dashboard(events: list[dict[str, Any]], replay: list[dict[str, Any]], iocs: list[dict[str, Any]], stats: dict[str, Any], diagnostics: list[dict[str, str]]) -> str:
    event_json = json.dumps(events, ensure_ascii=False).replace("</", "<\\/")
    replay_json = json.dumps(replay, ensure_ascii=False).replace("</", "<\\/")
    ioc_json = json.dumps(iocs, ensure_ascii=False).replace("</", "<\\/")
    stats_json = json.dumps(stats, ensure_ascii=False).replace("</", "<\\/")
    diag_json = json.dumps(diagnostics, ensure_ascii=False).replace("</", "<\\/")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Agent DFIR Investigation</title>
<style>
:root{{--bg:#f3f6fa;--panel:#fff;--ink:#182230;--muted:#64748b;--line:#dbe3ec;--accent:#2563eb;--accent-dark:#1e40af;--warn:#8a5a00;--shadow:0 8px 24px rgba(15,23,42,.06)}}
*{{box-sizing:border-box}}body{{margin:0;font-family:Inter,"Segoe UI",Arial,sans-serif;background:var(--bg);color:var(--ink);line-height:1.45}}
header{{background:linear-gradient(125deg,#111827 0%,#1e3a5f 58%,#1d4ed8 140%);color:#fff;padding:26px max(28px,calc((100vw - 1440px)/2));box-shadow:0 2px 14px rgba(15,23,42,.2)}}.brand{{display:flex;align-items:center;gap:15px}}.brand-mark{{width:48px;height:48px;flex:0 0 auto;filter:drop-shadow(0 4px 8px rgba(0,0,0,.22))}}.brand-copy{{min-width:0}}header h1{{margin:0;font-size:28px;letter-spacing:-.02em}}header p{{margin:4px 0 0;color:#cbd5e1;max-width:780px}}.brand-tag{{display:inline-block;margin-left:9px;padding:3px 7px;border:1px solid rgba(255,255,255,.3);border-radius:999px;color:#bfdbfe;font-size:10px;letter-spacing:.08em;text-transform:uppercase;vertical-align:middle}}
nav{{display:flex;gap:6px;flex-wrap:wrap;padding:10px max(28px,calc((100vw - 1440px)/2));background:rgba(255,255,255,.96);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5;backdrop-filter:blur(10px)}}
button,nav button{{font:inherit;border:1px solid var(--line);background:#fff;color:#334155;padding:8px 13px;border-radius:8px;cursor:pointer;transition:.15s ease}}button:hover,nav button:hover{{border-color:#93b4e8;background:#f8fbff}}nav button.active{{background:var(--accent);border-color:var(--accent);color:white;box-shadow:0 3px 9px rgba(37,99,235,.25)}}
main{{max-width:1496px;margin:0 auto;padding:22px 28px 40px}}.view{{display:none}}.view.active{{display:block}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:14px 0 22px}}
.card{{background:linear-gradient(180deg,#fff,#fbfdff);border:1px solid var(--line);border-radius:12px;padding:16px 17px;min-width:145px;box-shadow:var(--shadow);color:var(--muted)}}.card strong{{font-size:25px;line-height:1.2;display:block;color:var(--ink);margin-bottom:4px}}
.panel{{background:var(--panel);border:1px solid var(--line);border-radius:12px;margin:14px 0;overflow:hidden;box-shadow:var(--shadow)}}.panel h2{{font-size:16px;margin:0;padding:14px 17px;background:#f8fafc;border-bottom:1px solid var(--line)}}
.controls{{display:flex;gap:9px;flex-wrap:wrap;align-items:center;margin:2px 0 14px;padding:12px;background:#fff;border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow)}}input,select{{font:inherit;padding:9px 11px;border:1px solid #cbd5e1;border-radius:8px;background:#fff;min-height:39px}}input:focus,select:focus{{outline:3px solid #dbeafe;border-color:#60a5fa}}input[type=checkbox]{{min-height:auto}}
table{{border-collapse:collapse;width:100%;table-layout:fixed}}th,td{{border-top:1px solid #e5e7e9;padding:8px 10px;text-align:left;vertical-align:top;font-size:12px;word-break:break-word}}th{{background:#f7f9fa;color:#475569;font-size:11px;letter-spacing:.035em;text-transform:uppercase}}tbody tr:hover{{background:#f8fbff}}
.time-cell{{white-space:nowrap;font-variant-numeric:tabular-nums;color:#334155}}.event-badge{{display:inline-flex;padding:3px 7px;border-radius:6px;background:#e8eef7;color:#334155;font-size:10px;font-weight:750;letter-spacing:.02em}}.source-cell{{color:var(--muted);line-height:1.35}}.source-file{{display:block;color:#334155;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}.event-summary{{line-height:1.4}}.evidence-toggle{{margin-top:5px;color:var(--accent);cursor:pointer}}
.secret-panel{{border-color:#fecaca}}.secret-panel h2{{background:#fff7f7;color:#991b1b}}.secret-value{{display:block;max-width:360px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:#9f1239;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}.secret-hash{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:10px;color:var(--muted);overflow-wrap:anywhere}}.finding-type{{display:inline-flex;padding:3px 7px;border-radius:6px;background:#fff1f2;color:#be123c;border:1px solid #fecdd3;font-size:10px;font-weight:750}}.secret-note{{padding:11px 15px;background:#fffbeb;border-bottom:1px solid #fde68a;color:#713f12;font-size:12px}}
pre{{white-space:pre-wrap;max-height:350px;overflow:auto;background:#f7f7f7;border:1px solid #ddd;padding:8px}}
.conversation{{max-width:1120px;margin:0 auto;padding:2px 0}}
.replay-count{{margin-left:auto;color:var(--muted);font-size:13px}}
.date-group{{background:#fff;border:1px solid var(--line);border-radius:13px;margin:0 0 14px;overflow:hidden;box-shadow:var(--shadow)}}
.date-group>summary{{list-style:none;cursor:pointer;display:flex;align-items:center;gap:10px;padding:14px 17px;font-weight:700;background:#f8fafc}}.date-group>summary::-webkit-details-marker{{display:none}}.date-group>summary::before{{content:'›';font-size:22px;line-height:1;color:var(--accent);transform:rotate(0);transition:transform .15s}}.date-group[open]>summary::before{{transform:rotate(90deg)}}
.date-title{{font-size:15px}}.date-iso{{font-size:12px;color:var(--muted);font-weight:500}}.date-count{{margin-left:auto;background:#e8eef7;color:#475569;border-radius:999px;padding:3px 9px;font-size:11px}}
.date-messages{{padding:16px 18px 13px;background:linear-gradient(180deg,#fbfdff,#fff)}}.date-messages>.message:first-child{{margin-top:0}}
.message{{max-width:84%;padding:14px 16px;margin:13px 0;border-radius:14px;box-shadow:0 2px 7px rgba(15,23,42,.07)}}
.message.user{{margin-left:auto;background:#e8f1ff;border:1px solid #b9d2fb;border-bottom-right-radius:4px}}
.message.agent{{margin-right:auto;background:#edfbf5;border:1px solid #b7ead4;border-bottom-left-radius:4px}}
.message-head{{display:flex;gap:8px;align-items:center;margin-bottom:7px;font-size:12px;font-weight:700}}
.message-body{{white-space:pre-wrap;font-size:14px;line-height:1.55;overflow-wrap:anywhere}}.message-image{{display:block;max-width:100%;max-height:720px;width:auto;height:auto;margin:12px auto;border:1px solid #cbd5e1;border-radius:10px;background:#fff;box-shadow:0 5px 18px rgba(15,23,42,.12);object-fit:contain}}.image-label{{display:block;margin:9px 0 5px;color:var(--muted);font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase}}.message-time{{margin-left:auto;font-weight:500;font-variant-numeric:tabular-nums}}
.role-user{{color:#1d4ed8}}.role-agent{{color:#047857}}.muted{{color:var(--muted)}}
.badge{{display:inline-block;padding:2px 7px;border-radius:10px;background:#e2e8f0;font-size:11px;margin-right:4px}}.warning{{background:#fffbeb;border:1px solid #fde68a;padding:12px 14px;border-radius:10px;color:#713f12}}
.bar{{height:12px;background:var(--accent);display:inline-block;min-width:2px}}.hidden{{display:none}}
.graph-wrap{{overflow:auto;background:#fbfcfd;border-top:1px solid var(--line);min-height:520px}}
#activityGraph{{display:block;min-width:100%;font-family:Segoe UI,Arial,sans-serif}}
.graph-node{{cursor:pointer;filter:drop-shadow(0 1px 1px rgba(0,0,0,.12))}}
.graph-node:hover rect{{stroke-width:3}}
.graph-edge{{stroke:#91a4b7;stroke-width:1.6;fill:none;marker-end:url(#arrow)}}
.graph-edge.tool{{stroke:#8a6d3b}}.graph-edge.file{{stroke:#577590}}
.graph-label{{font-size:11px;fill:#17202a;pointer-events:none}}
.graph-sub{{font-size:9px;fill:#5d6d7e;pointer-events:none}}
.graph-lane{{font-size:11px;font-weight:700;fill:#425466}}
.graph-card-body{{height:100%;padding:10px 11px 8px;overflow:hidden;color:#17202a;font-family:Segoe UI,Arial,sans-serif}}
.graph-card-title{{display:-webkit-box;-webkit-box-orient:vertical;-webkit-line-clamp:3;overflow:hidden;font-size:11px;font-weight:600;line-height:1.35;overflow-wrap:anywhere;word-break:break-word}}
.graph-card-meta{{position:absolute;left:11px;right:11px;bottom:7px;display:flex;justify-content:space-between;gap:8px;color:#5d6d7e;font-size:9px;white-space:nowrap;overflow:hidden}}
.graph-card-meta span{{overflow:hidden;text-overflow:ellipsis}}
.graph-card-badge{{display:inline-block;margin-bottom:5px;padding:2px 6px;border-radius:9px;background:rgba(255,255,255,.62);border:1px solid rgba(76,94,112,.22);color:#40566c;font-size:8px;font-weight:700;letter-spacing:.04em;text-transform:uppercase}}
.graph-empty{{padding:30px;color:var(--muted)}}
.graph-legend{{display:flex;gap:14px;flex-wrap:wrap;padding:10px 14px;border-bottom:1px solid var(--line);font-size:11px}}
.graph-key{{display:inline-flex;align-items:center;gap:5px}}
.graph-swatch{{width:13px;height:13px;border-radius:3px;border:1px solid rgba(0,0,0,.2)}}
.graph-detail{{padding:13px 15px;border-top:1px solid var(--line);background:#f8fafb;min-height:95px}}
.graph-detail pre{{max-height:230px;margin:8px 0 0}}
.trace-layout{{display:grid;grid-template-columns:minmax(0,1fr) 390px;min-height:560px}}.trace-list{{padding:16px 20px 28px;border-right:1px solid var(--line);min-width:0}}.trace-inspector{{position:sticky;top:64px;align-self:start;max-height:calc(100vh - 82px);overflow:auto;padding:18px;background:#f8fafc}}.trace-inspector pre{{max-height:none}}
.trace-session{{border:1px solid var(--line);border-radius:11px;margin-bottom:14px;overflow:hidden;background:#fff}}.trace-session>summary{{cursor:pointer;display:flex;gap:10px;align-items:center;padding:12px 14px;background:#f8fafc;font-weight:700}}.trace-session-title{{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}.trace-session-meta{{margin-left:auto;white-space:nowrap;font-size:11px;color:var(--muted);font-weight:500}}
.trace-events{{padding:13px 15px 15px}}.trace-item{{position:relative;margin-left:18px;padding:0 0 17px 26px;border-left:2px solid #cbd5e1}}.trace-item:last-child{{padding-bottom:2px}}.trace-dot{{position:absolute;left:-8px;top:13px;width:14px;height:14px;border-radius:50%;border:3px solid #fff;box-shadow:0 0 0 1px #94a3b8;background:#94a3b8}}.trace-item.user .trace-dot{{background:#3b82f6}}.trace-item.assistant .trace-dot{{background:#10b981}}.trace-item.tool .trace-dot{{background:#f59e0b}}.trace-item.file .trace-dot{{background:#6366f1}}
.trace-card{{cursor:pointer;border:1px solid var(--line);border-radius:10px;padding:11px 13px;background:#fff;transition:.15s ease}}.trace-card:hover,.trace-card.selected{{border-color:#60a5fa;box-shadow:0 3px 12px rgba(37,99,235,.12)}}.trace-card.user{{background:#eff6ff}}.trace-card.assistant{{background:#ecfdf5}}.trace-head{{display:flex;gap:7px;align-items:center;font-size:11px;color:var(--muted);margin-bottom:5px}}.trace-title{{font-size:13px;font-weight:650;line-height:1.4;display:-webkit-box;-webkit-box-orient:vertical;-webkit-line-clamp:3;overflow:hidden}}.risk-badge{{padding:2px 6px;border-radius:999px;font-size:9px;font-weight:700;text-transform:uppercase;background:#fff1f2;color:#be123c;border:1px solid #fecdd3}}
.action-group{{margin:7px 0 0 12px}}.action-group>summary{{cursor:pointer;color:#475569;font-size:12px;font-weight:650;padding:5px 0}}.action-list{{display:grid;gap:6px;padding:3px 0 2px 10px;border-left:2px solid #e2e8f0}}.action-row{{cursor:pointer;display:flex;gap:8px;align-items:flex-start;padding:7px 9px;border:1px solid #e2e8f0;border-radius:7px;background:#fafafa;font-size:11px}}.action-row:hover{{border-color:#93c5fd;background:#f8fbff}}.action-time{{margin-left:auto;color:var(--muted);white-space:nowrap}}
@media(max-width:1000px){{.trace-layout{{grid-template-columns:1fr}}.trace-list{{border-right:0}}.trace-inspector{{position:relative;top:auto;max-height:none;border-top:1px solid var(--line)}}}}
@media(max-width:700px){{header{{padding:22px 18px}}nav{{padding:9px 12px;flex-wrap:nowrap;overflow-x:auto}}main{{padding:16px 12px 30px}}.controls input{{width:100%}}.message{{max-width:94%}}.date-messages{{padding:4px 10px 10px}}table{{min-width:720px}}.panel{{overflow:auto}}}}
</style></head><body>
<header><div class="brand"><svg class="brand-mark" viewBox="0 0 64 64" role="img" aria-label="AI Agent DFIR shield"><defs><linearGradient id="shieldGradient" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#93c5fd"/><stop offset="1" stop-color="#38bdf8"/></linearGradient></defs><path d="M32 3 55 12v17c0 15-9.7 25.4-23 32C18.7 54.4 9 44 9 29V12L32 3Z" fill="url(#shieldGradient)" stroke="#dbeafe" stroke-width="2"/><path d="M20 38V25l12-7 12 7v13l-12 7-12-7Z" fill="#10233e" opacity=".94"/><circle cx="32" cy="31.5" r="4.5" fill="#7dd3fc"/><path d="M32 27v-5M28 29l-5-3M28 35l-5 3M36 29l5-3M36 35l5 3M32 36v5" stroke="#e0f2fe" stroke-width="2" stroke-linecap="round"/></svg><div class="brand-copy"><h1>AI Agent DFIR Investigation <span class="brand-tag">Forensic Report</span></h1><p>Cross-agent activity reconstruction, graph analysis, analytics, IOC extraction, and case replay</p></div></div></header>
<nav>
<button data-view="overview" class="active">Overview</button><button data-view="replay">Case Replay</button>
<button data-view="timeline">Timeline</button><button data-view="graph">Activity Graph</button><button data-view="iocs">IOCs</button>
<button data-view="analytics">Analytics</button><button data-view="diagnostics">Ingestion</button>
</nav><main>
<section id="overview" class="view active"><div class="warning">Automated classification and IOC extraction are investigative leads, not final attribution. Validate against raw artifacts and hashes.</div><div id="cards" class="cards"></div><div class="panel"><h2>Agent usage</h2><div id="agentChart" style="padding:14px"></div></div><div class="panel"><h2>Event distribution</h2><div id="typeChart" style="padding:14px"></div></div></section>
<section id="replay" class="view"><div class="controls"><input id="replaySearch" size="45" placeholder="Search prompts and responses"><select id="replayAgent"><option value="">All agents</option></select><button id="replayExpand" type="button">Expand all</button><button id="replayCollapse" type="button">Collapse all</button><span id="replayCount" class="replay-count"></span></div><div id="replayRows" class="conversation"></div></section>
<section id="timeline" class="view"><div class="controls"><input id="eventSearch" size="45" placeholder="Search prompts, commands, files, IDs"><select id="eventType"><option value="">All event types</option></select><select id="eventAgent"><option value="">All agents</option></select><label><input id="showInternal" type="checkbox"> Show internal records</label></div><div class="panel"><table><thead><tr><th style="width:178px">Date &amp; time (UTC)</th><th style="width:100px">Agent</th><th style="width:145px">Type</th><th>Summary / evidence</th><th style="width:180px">Source</th></tr></thead><tbody id="eventRows"></tbody></table></div></section>
<section id="graph" class="view">
<div class="controls">
<select id="graphMode"><option value="trace" selected>Investigation trace</option><option value="advanced">Advanced graph</option></select>
<select id="graphDensity"><option value="all" selected>Everything</option><option value="conversation">Prompts &amp; responses only</option><option value="actions">Actions only</option></select>
<select id="graphAgent"><option value="">All agents</option></select>
<select id="graphSession"><option value="">All conversations</option></select>
<label><input id="graphInternal" type="checkbox"> Include internal records</label>
<label><input id="graphLowLevel" type="checkbox"> Include low-level Codex events</label>
<button id="graphReset" type="button">Reset selection</button>
</div>
<div id="graphTrace" class="panel"><h2>Investigation Trace</h2><div class="trace-layout"><div id="traceRows" class="trace-list"></div><aside id="traceDetail" class="trace-inspector"><b>Evidence inspector</b><p class="muted">Select an event to inspect its full evidence and source information.</p></aside></div></div>
<div id="graphAdvanced" class="panel hidden">
<h2>AI Agent Activity Graph</h2>
<div class="graph-legend">
<span class="graph-key"><span class="graph-swatch" style="background:#dbeafe"></span>User prompt</span>
<span class="graph-key"><span class="graph-swatch" style="background:#dcfce7"></span>Assistant response</span>
<span class="graph-key"><span class="graph-swatch" style="background:#fef3c7"></span>Command / tool</span>
<span class="graph-key"><span class="graph-swatch" style="background:#e0e7ff"></span>File / target</span>
<span class="graph-key"><span class="graph-swatch" style="background:#f3e8ff"></span>Other evidence</span>
</div>
<div class="graph-wrap"><svg id="activityGraph" role="img" aria-label="AI agent activity flow graph"></svg></div>
<div id="graphDetail" class="graph-detail"><span class="muted">Select a node to inspect its evidence.</span></div>
</div>
</section>
<section id="iocs" class="view"><div class="controls"><input id="iocSearch" size="40" placeholder="Search indicators"><select id="iocType"><option value="">All IOC types</option></select></div><div class="panel"><table><thead><tr><th style="width:130px">Type</th><th>Value</th><th style="width:90px">Count</th><th>Agents</th><th>Source events</th></tr></thead><tbody id="iocRows"></tbody></table></div></section>
<section id="analytics" class="view"><div id="analyticsBody"></div></section>
<section id="diagnostics" class="view"><div class="panel"><h2>File ingestion diagnostics</h2><table><thead><tr><th>File</th><th style="width:110px">Status</th><th>Detail</th></tr></thead><tbody id="diagRows"></tbody></table></div></section>
</main>
<script>
const EVENTS={event_json}, REPLAY={replay_json}, IOCS={ioc_json}, STATS={stats_json}, DIAGS={diag_json};
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));
document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>{{document.querySelectorAll('nav button,.view').forEach(x=>x.classList.remove('active'));b.classList.add('active');document.getElementById(b.dataset.view).classList.add('active');if(b.dataset.view==='graph')renderGraph()}});
function options(el, values){{[...values].sort().forEach(v=>el.insertAdjacentHTML('beforeend',`<option value="${{esc(v)}}">${{esc(v)}}</option>`))}}
function renderCards(){{const exposed=secretRecords(EVENTS).filter(x=>x.scope==='content').length,vals=[['Events',STATS.total_events],['Conversations',STATS.sessions],['Turns',STATS.turns],['Processes',STATS.processes],['IOCs',STATS.ioc_count],['Input tokens',STATS.token_usage.input],['Output tokens',STATS.token_usage.output],['User-exposed secrets',exposed]];cards.innerHTML=vals.map(x=>`<div class=card><strong>${{typeof x[1]==='number'?x[1].toLocaleString():esc(x[1])}}</strong>${{esc(x[0])}}</div>`).join('')}}
function bars(el,obj){{const entries=Object.entries(obj).sort((a,b)=>b[1]-a[1]), max=Math.max(1,...entries.map(x=>x[1]));el.innerHTML=entries.map(([k,v])=>`<div style="margin:7px 0"><span style="display:inline-block;width:170px">${{esc(k)}}</span><span class=bar style="width:${{Math.max(2,400*v/max)}}px"></span> ${{v}}</div>`).join('')||'<span class=muted>No data</span>'}}
function replayDate(value){{if(!value)return {{key:'unknown',title:'Date unavailable',iso:''}};const d=new Date(value);if(Number.isNaN(d.getTime()))return {{key:String(value).slice(0,10)||'unknown',title:String(value).slice(0,10)||'Date unavailable',iso:'UTC'}};return {{key:d.toISOString().slice(0,10),title:new Intl.DateTimeFormat(undefined,{{weekday:'long',year:'numeric',month:'long',day:'numeric',timeZone:'UTC'}}).format(d),iso:'UTC'}}}}
function replayTime(value){{if(!value)return 'Time unavailable';const d=new Date(value);if(Number.isNaN(d.getTime()))return String(value);return new Intl.DateTimeFormat(undefined,{{hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false,timeZone:'UTC',timeZoneName:'short'}}).format(d)}}
function replayBody(message){{const image=/data:image\\/(?:png|jpeg|jpg|gif|webp);base64,[A-Za-z0-9+/]+={{0,2}}/gi;let last=0,out='',match,index=0;while((match=image.exec(String(message||'')))!==null){{out+=esc(String(message).slice(last,match.index).replace(/input_image\\s*$/i,''));out+=`<span class=image-label>Attached image ${{++index}}</span><img class=message-image src="${{match[0]}}" alt="User-provided image ${{index}}" loading="lazy">`;last=match.index+match[0].length}}return out+esc(String(message||'').slice(last))}}
function replayMessage(x){{const isUser=x.role==='user',label=isUser?'USER':'AGENT',roleClass=isUser?'role-user':'role-agent',agentLabel=isUser?'':`<span class=badge>${{esc(x.agent)}}</span>`;return `<article class="message ${{isUser?'user':'agent'}}"><div class=message-head><span class=${{roleClass}}>${{label}}</span>${{agentLabel}}<time class="muted message-time" datetime="${{esc(x.timestamp_utc||'')}}">${{esc(replayTime(x.timestamp_utc))}}</time></div><div class=message-body>${{replayBody(x.message)}}</div></article>`}}
function renderReplay(){{const q=replaySearch.value.toLowerCase(),a=replayAgent.value,rows=REPLAY.filter(x=>(!q||String(x.message).toLowerCase().includes(q))&&(!a||x.agent===a)),groups=new Map();rows.forEach(x=>{{const d=replayDate(x.timestamp_utc);if(!groups.has(d.key))groups.set(d.key,{{date:d,items:[]}});groups.get(d.key).items.push(x)}});replayCount.textContent=`${{rows.length.toLocaleString()}} message${{rows.length===1?'':'s'}} · ${{groups.size}} date${{groups.size===1?'':'s'}}`;replayRows.innerHTML=[...groups.values()].map((g,i)=>`<details class=date-group ${{i<3?'open':''}}><summary><span class=date-title>${{esc(g.date.title)}}</span><span class=date-iso>${{esc(g.date.iso)}}</span><span class=date-count>${{g.items.length}} message${{g.items.length===1?'':'s'}}</span></summary><div class=date-messages>${{g.items.map(replayMessage).join('')}}</div></details>`).join('')||'<div class="panel graph-empty">No prompts or responses matched.</div>'}}
function timelineTime(value){{if(!value)return 'Time unavailable';const d=new Date(value);return Number.isNaN(d.getTime())?String(value):`${{d.toISOString().slice(0,10)}} ${{d.toISOString().slice(11,19)}} UTC`}}
function sourceName(value){{const parts=String(value||'Unknown source').replace(/\\\\/g,'/').split('/');return parts[parts.length-1]||'Unknown source'}}
function renderEvents(){{const q=eventSearch.value.toLowerCase(),t=eventType.value,a=eventAgent.value;const internal=new Set(['SYSTEM CONFIGURATION','DEVELOPER INSTRUCTION','ENVIRONMENT CONTEXT','SESSION METADATA']);eventRows.innerHTML=EVENTS.filter(x=>(showInternal.checked||!internal.has(x.event_type))&&(!q||JSON.stringify(x).toLowerCase().includes(q))&&(!t||x.event_type===t)&&(!a||x.agent===a)).map(x=>`<tr><td class=time-cell title="${{esc(x.timestamp_utc)}}">${{esc(timelineTime(x.timestamp_utc))}}</td><td><span class=badge>${{esc(x.agent)}}</span></td><td><span class=event-badge>${{esc(x.event_type)}}</span></td><td class=event-summary><b>#${{x.event_number}} · ${{esc(x.summary)}}</b><details><summary class=evidence-toggle>View evidence</summary><pre>${{esc(x.text||x.details)}}</pre></details></td><td class=source-cell title="${{esc(x.source_file)}}"><span class=source-file>${{esc(sourceName(x.source_file))}}:${{esc(x.source_line)}}</span>${{esc(x.source_type)}}</td></tr>`).join('')}}

const GRAPH_INTERNAL=new Set(['SYSTEM CONFIGURATION','DEVELOPER INSTRUCTION','ENVIRONMENT CONTEXT','SESSION METADATA']);
function graphIsLowLevel(e){{if(String(e.agent||'').toLowerCase()!=='codex')return false;const type=String(e.event_type||'').toUpperCase(),action=String(e.action||''),source=String(e.source_type||'').toLowerCase();if(type==='WARNING / ERROR')return false;if(['RUNTIME','SESSION','MODEL / TOKEN','SESSION METADATA','DEVELOPER INSTRUCTION','SYSTEM CONFIGURATION','ENVIRONMENT CONTEXT'].includes(type))return true;if(action==='RuntimeToolEvent'||action==='SQLiteRecord')return true;if(source.startsWith('sqlite:')&&(type==='USER PROMPT'||type==='ASSISTANT RESPONSE'))return true;return false}}
function graphAvailableEvents(){{return EVENTS.filter(e=>!(String(e.agent||'').toLowerCase()==='codex'&&String(e.tool_name||'').toLowerCase()==='exec')).filter(e=>graphLowLevel.checked||!graphIsLowLevel(e))}}
function graphKind(e){{
  const t=String(e.event_type||'').toUpperCase(),a=String(e.action||'').toLowerCase();
  if(t==='USER PROMPT')return 'user';
  if(t==='ASSISTANT RESPONSE')return 'assistant';
  if(t.includes('COMMAND')||a.includes('exec')||a==='run_command'||e.tool_name)return 'tool';
  if(e.target||a.includes('file')||a.includes('directory'))return 'file';
  return 'other';
}}
function graphColor(k){{return {{user:'#dbeafe',assistant:'#dcfce7',tool:'#fef3c7',file:'#e0e7ff',other:'#f3e8ff'}}[k]}}
function graphBasename(value){{
  const parts=String(value||'').replace(/\\\\/g,'/').split('/');
  return parts[parts.length-1]||String(value||'');
}}
function graphPreview(e){{
  const kind=graphKind(e);
  if(kind==='user'||kind==='assistant'){{
    return String(e.text||e.summary||e.details||e.event_type||'').replace(/\\s+/g,' ').trim();
  }}
  if(kind==='tool'){{
    const tool=String(e.tool_name||e.action||'Tool activity').replace(/_/g,' ');
    const command=Array.isArray(e.commands)&&e.commands.length?e.commands[0]:'';
    const target=e.target?graphBasename(e.target):'';
    if(command)return `${{tool}}: ${{command}}`;
    if(target)return `${{tool}} → ${{target}}`;
    return tool;
  }}
  if(kind==='file'){{
    const action=String(e.action||'File activity').replace(/_/g,' ');
    return e.target?`${{action}} → ${{graphBasename(e.target)}}`:action;
  }}
  return String(e.summary||e.action||e.event_type||'Event').replace(/\\s+/g,' ').trim();
}}
function graphBadge(e){{
  const kind=graphKind(e);
  if(kind==='user')return 'User prompt';
  if(kind==='assistant')return 'Assistant reply';
  if(kind==='tool')return e.tool_name?String(e.tool_name).replace(/_/g,' '):'Tool / command';
  if(kind==='file')return 'File activity';
  return String(e.event_type||'Evidence').replace(/_/g,' ');
}}
function graphSessions(events){{
  const counts={{}};
  events.forEach(e=>{{const k=e.session_key||e.session_id||e.correlation_key||'uncorrelated';counts[k]=(counts[k]||0)+1}});
  return counts;
}}
function refreshGraphSessions(){{
  const agent=graphAgent.value;
  const current=graphSession.value;
  const vals=Object.keys(graphSessions(graphAvailableEvents().filter(e=>!agent||e.agent===agent))).sort();
  graphSession.innerHTML='<option value="">All conversations</option>'+vals.map(v=>{{const items=graphAvailableEvents().filter(e=>(e.session_key||e.session_id||e.correlation_key||'uncorrelated')===v&&(!agent||e.agent===agent));return `<option value="${{esc(v)}}">${{esc(traceSessionTitle(items))}}</option>`}}).join('');
  if(vals.includes(current))graphSession.value=current;
}}
function graphDetailHtml(e){{
  const body=e.text||e.details||'No additional evidence text.';
  return `<b>#${{esc(e.event_number)}} · ${{esc(e.event_type)}} · ${{esc(e.agent)}}</b>
  <div class=muted>${{esc(e.timestamp_utc)}} · Session: ${{esc(e.session_key||e.session_id||'uncorrelated')}}</div>
  <div>${{esc(e.summary||e.action||'')}}</div>
  <pre>${{esc(body)}}</pre>
  <div class=muted>Source: ${{esc(e.source_file)}}:${{esc(e.source_line)}} · SHA-256: ${{esc(e.evidence_hash)}}</div>`;
}}
function traceRisks(e){{const risks=[];if(Array.isArray(e.secret_findings)&&e.secret_findings.length)risks.push('Secret');if((e.urls||[]).length||(e.domains||[]).length||String(e.event_type||'').toLowerCase().includes('network'))risks.push('Network');if((e.commands||[]).length||graphKind(e)==='tool')risks.push('Command');if(e.target||graphKind(e)==='file')risks.push('File');if(/error|fail|denied/i.test(`${{e.level||''}} ${{e.summary||''}}`))risks.push('Error');return [...new Set(risks)]}}
function traceBadges(e){{return traceRisks(e).map(x=>`<span class=risk-badge>${{esc(x)}}</span>`).join('')}}
function traceEventCard(e,index){{const kind=graphKind(e),preview=graphPreview(e)||'No summary available';return `<div class="trace-card ${{kind}}" data-event-index="${{index}}" tabindex="0"><div class=trace-head><span class=badge>${{esc(graphBadge(e))}}</span>${{traceBadges(e)}}<span class=action-time>${{esc((e.timestamp_utc||'').slice(11,19))}} UTC</span></div><div class=trace-title title="${{esc(preview)}}">${{esc(preview)}}</div></div>`}}
function traceActionRow(e,index){{return `<div class=action-row data-event-index="${{index}}" tabindex="0"><span class=badge>${{esc(graphBadge(e))}}</span><span>${{esc(graphPreview(e)||e.summary||'Event')}}</span>${{traceBadges(e)}}<span class=action-time>${{esc((e.timestamp_utc||'').slice(11,19))}}</span></div>`}}
function traceSessionTitle(items){{const first=items.find(e=>graphKind(e)==='user')||items[0],date=(first.timestamp_utc||'Date unavailable').slice(0,10),agent=first.agent||'unknown agent',prompt=graphPreview(first).slice(0,72);return `${{date}} · ${{agent}} · ${{prompt||'Session activity'}}`}}
function bindTraceEvents(){{const nodes=[...document.querySelectorAll('#graphTrace [data-event-index]')];nodes.forEach((n,i)=>{{n.onclick=ev=>{{ev.stopPropagation();const e=EVENTS[Number(n.dataset.eventIndex)];traceDetail.innerHTML=graphDetailHtml(e);nodes.forEach(x=>x.classList.remove('selected'));n.classList.add('selected')}};n.onkeydown=ev=>{{if(ev.key==='Enter'||ev.key===' '){{ev.preventDefault();n.click()}}else if(ev.key==='ArrowDown'||ev.key==='ArrowUp'){{ev.preventDefault();const next=nodes[i+(ev.key==='ArrowDown'?1:-1)];if(next){{next.focus();next.click()}}}}}}}})}}
function renderTrace(){{const agent=graphAgent.value,session=graphSession.value,density=graphDensity.value;let rows=graphAvailableEvents().filter(e=>(graphInternal.checked||!GRAPH_INTERNAL.has(e.event_type))&&(!agent||e.agent===agent)&&(!session||(e.session_key||e.session_id||e.correlation_key||'uncorrelated')===session));const groups=new Map();rows.forEach(e=>{{const k=e.session_key||e.session_id||e.correlation_key||'uncorrelated';if(!groups.has(k))groups.set(k,[]);groups.get(k).push(e)}});traceRows.innerHTML=[...groups.entries()].map(([key,items],sessionIndex)=>{{let body='';if(density==='actions'){{body=items.map(e=>{{const kind=graphKind(e);if(kind==='user'||kind==='assistant')return '';return `<div class="trace-item ${{kind}}"><span class=trace-dot></span>${{traceEventCard(e,EVENTS.indexOf(e))}}</div>`}}).join('')}}else{{const blocks=[],preamble=[];let current=null;items.forEach(e=>{{const kind=graphKind(e);if(kind==='user'||kind==='assistant'){{current={{anchor:e,actions:[]}};blocks.push(current)}}else if(current)current.actions.push(e);else preamble.push(e)}});if(preamble.length&&density==='all')body+=`<details class=action-group><summary>${{preamble.length}} session setup event${{preamble.length===1?'':'s'}}</summary><div class=action-list>${{preamble.map(e=>traceActionRow(e,EVENTS.indexOf(e))).join('')}}</div></details>`;body+=blocks.map(b=>{{const kind=graphKind(b.anchor),actions=density==='all'&&b.actions.length?`<details class=action-group><summary>${{b.actions.length}} related action${{b.actions.length===1?'':'s'}}</summary><div class=action-list>${{b.actions.map(e=>traceActionRow(e,EVENTS.indexOf(e))).join('')}}</div></details>`:'';return `<div class="trace-item ${{kind}}"><span class=trace-dot></span>${{traceEventCard(b.anchor,EVENTS.indexOf(b.anchor))}}${{actions}}</div>`}}).join('')}}if(!body)return '';return `<details class=trace-session ${{sessionIndex<3?'open':''}}><summary><span class=trace-session-title>${{esc(traceSessionTitle(items))}}</span><span class=trace-session-meta>${{items.length}} events</span></summary><div class=trace-events>${{body}}</div></details>`}}).join('')||'<div class=graph-empty>No events matched the selected filters.</div>';traceDetail.innerHTML=`<b>Evidence inspector</b><p class=muted>Showing ${{rows.length}} events across ${{groups.size}} conversation group(s). Select an event to inspect its evidence.</p>`;bindTraceEvents()}}
function renderGraph(){{const advanced=graphMode.value==='advanced';graphTrace.classList.toggle('hidden',advanced);graphAdvanced.classList.toggle('hidden',!advanced);graphDensity.disabled=advanced;if(advanced)renderAdvancedGraph();else renderTrace()}}
function renderAdvancedGraph(){{
  const agent=graphAgent.value,session=graphSession.value;
  let rows=graphAvailableEvents().filter(e=>(graphInternal.checked||!GRAPH_INTERNAL.has(e.event_type))&&(!agent||e.agent===agent)&&(!session||(e.session_key||e.session_id||e.correlation_key||'uncorrelated')===session));
  if(!rows.length){{activityGraph.innerHTML='';activityGraph.setAttribute('height','0');activityGraph.parentElement.innerHTML='<div class=graph-empty>No graphable events matched the selected filters.</div>';return}}
  if(!activityGraph.parentElement.querySelector('svg')){{activityGraph.parentElement.innerHTML='<svg id="activityGraph" role="img" aria-label="AI agent activity flow graph"></svg>';window.activityGraph=document.getElementById('activityGraph')}}
  const groups=new Map();
  rows.forEach(e=>{{const k=e.session_key||e.session_id||e.correlation_key||'uncorrelated';if(!groups.has(k))groups.set(k,[]);groups.get(k).push(e)}});
  const nodeW=250,nodeH=94,gapX=58,laneH=142,left=165,top=42;
  const maxCols=Math.max(...[...groups.values()].map(v=>v.length));
  const width=Math.max(1050,left+maxCols*(nodeW+gapX)+50),height=Math.max(300,top+groups.size*laneH+50);
  activityGraph.setAttribute('viewBox',`0 0 ${{width}} ${{height}}`);
  activityGraph.setAttribute('width',width);activityGraph.setAttribute('height',height);
  let svg=`<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#91a4b7"/></marker></defs>`;
  [...groups.entries()].forEach(([key,items],lane)=>{{
    const y=top+lane*laneH;
    svg+=`<text class="graph-lane" x="12" y="${{y+28}}">${{esc(key.length>22?key.slice(0,19)+'…':key)}}</text>`;
    svg+=`<text class="graph-sub" x="12" y="${{y+46}}">${{items.length}} events · scroll horizontally</text>`;
    items.forEach((e,i)=>{{
      const x=left+i*(nodeW+gapX),kind=graphKind(e);
      if(i>0){{const px=left+(i-1)*(nodeW+gapX)+nodeW;svg+=`<path class="graph-edge ${{kind}}" d="M ${{px}} ${{y+nodeH/2}} L ${{x-6}} ${{y+nodeH/2}}"/>`}}
      const preview=graphPreview(e);
      const badge=graphBadge(e);
      svg+=`<g class="graph-node" data-index="${{EVENTS.indexOf(e)}}" transform="translate(${{x}},${{y}})">
      <rect width="${{nodeW}}" height="${{nodeH}}" rx="10" fill="${{graphColor(kind)}}" stroke="#6b7f92" stroke-width="1.3"/>
      <foreignObject x="1" y="1" width="${{nodeW-2}}" height="${{nodeH-2}}" pointer-events="none">
        <div xmlns="http://www.w3.org/1999/xhtml" class="graph-card-body" style="position:relative">
          <div class="graph-card-badge">${{esc(badge)}}</div>
          <div class="graph-card-title" title="${{esc(preview)}}">${{esc(preview)}}</div>
          <div class="graph-card-meta">
            <span>#${{esc(e.event_number)}} · ${{esc((e.timestamp_utc||'').slice(11,19))}}</span>
            <span>${{esc(e.agent)}}</span>
          </div>
        </div>
      </foreignObject></g>`;
    }});
  }});
  activityGraph.innerHTML=svg;
  activityGraph.querySelectorAll('.graph-node').forEach(n=>n.onclick=()=>{{const e=EVENTS[Number(n.dataset.index)];graphDetail.innerHTML=graphDetailHtml(e);activityGraph.querySelectorAll('.graph-node rect').forEach(r=>r.setAttribute('stroke-width','1.3'));n.querySelector('rect').setAttribute('stroke-width','3')}});
  graphDetail.innerHTML=`<span class=muted>Showing ${{rows.length}} events across ${{groups.size}} conversation group(s). Select a node to inspect its evidence.</span>`;
}}
function renderIOCs(){{const q=iocSearch.value.toLowerCase(),t=iocType.value;iocRows.innerHTML=IOCS.filter(x=>(!q||JSON.stringify(x).toLowerCase().includes(q))&&(!t||x.type===t)).map(x=>`<tr><td>${{esc(x.type)}}</td><td>${{esc(x.value)}}</td><td>${{x.count}}</td><td>${{esc(x.agents.join(', '))}}</td><td>${{esc(x.source_events.join(', '))}}</td></tr>`).join('')}}
function kv(title,obj){{return `<div class=panel><h2>${{esc(title)}}</h2><table><tbody>${{Object.entries(obj).sort((a,b)=>b[1]-a[1]).map(([k,v])=>`<tr><td>${{esc(k)}}</td><td>${{esc(v)}}</td></tr>`).join('')||'<tr><td>No data</td></tr>'}}</tbody></table></div>`}}
renderCards();bars(agentChart,STATS.agents);bars(typeChart,STATS.event_types);
options(replayAgent,new Set(REPLAY.map(x=>x.agent)));options(eventType,new Set(EVENTS.map(x=>x.event_type)));options(eventAgent,new Set(EVENTS.map(x=>x.agent)));options(iocType,new Set(IOCS.map(x=>x.type)));
options(graphAgent,new Set(EVENTS.map(x=>x.agent)));refreshGraphSessions();
[replaySearch,replayAgent].forEach(x=>x.oninput=renderReplay);replayExpand.onclick=()=>document.querySelectorAll('.date-group').forEach(x=>x.open=true);replayCollapse.onclick=()=>document.querySelectorAll('.date-group').forEach(x=>x.open=false);[eventSearch,eventType,eventAgent,showInternal].forEach(x=>x.oninput=renderEvents);[iocSearch,iocType].forEach(x=>x.oninput=renderIOCs);
graphAgent.oninput=()=>{{refreshGraphSessions();renderGraph()}};[graphMode,graphDensity,graphSession,graphInternal].forEach(x=>x.oninput=renderGraph);graphLowLevel.oninput=()=>{{refreshGraphSessions();renderGraph()}};graphReset.onclick=()=>{{graphMode.value='trace';graphDensity.value='all';graphAgent.value='';graphLowLevel.checked=false;refreshGraphSessions();graphSession.value='';graphInternal.checked=false;renderGraph()}};
function secretRecords(events){{const records=new Map();events.forEach(e=>(e.secret_findings||[]).forEach(f=>{{const masked=String(f.masked||'[REDACTED]'),key=`${{f.type||'Potential secret'}}|${{masked}}`,isContent=['USER PROMPT','ASSISTANT RESPONSE'].includes(String(e.event_type||'').toUpperCase())||Boolean((e.metadata||{{}}).conversation_eligible);if(!records.has(key))records.set(key,{{type:f.type||'Potential secret',masked,sha256:f.sha256||'',first:e,events:new Set(),agents:new Set(),scope:'runtime',category:'Agent/runtime credential'}});const row=records.get(key);if(!row.sha256&&f.sha256)row.sha256=f.sha256;if(isContent){{row.scope='content';row.category='User/content exposure';row.first=e}}else if(row.scope!=='content'&&/set-cookie|cookie/i.test(`${{e.summary||''}} ${{e.details||''}}`))row.category='Infrastructure/session cookie';row.events.add(e.event_number);row.agents.add(e.agent)}}));return [...records.values()]}}
function secretRowsTable(rows){{return `<table><thead><tr><th style="width:170px">Classification</th><th style="width:140px">Type</th><th>Redacted value</th><th style="width:180px">First observed (UTC)</th><th style="width:105px">Agent</th><th style="width:125px">Evidence</th><th style="width:225px">SHA-256</th></tr></thead><tbody>${{rows.map(r=>`<tr><td><span class=event-badge>${{esc(r.category)}}</span></td><td><span class=finding-type>${{esc(r.type)}}</span></td><td><span class=secret-value title="${{esc(r.masked)}}">${{esc(r.masked)}}</span></td><td class=time-cell>${{esc(timelineTime(r.first.timestamp_utc))}}</td><td>${{esc([...r.agents].join(', '))}}</td><td>${{[...r.events].map(n=>`#${{n}}`).join(', ')}}</td><td class=secret-hash>${{esc(r.sha256||'Hash unavailable')}}</td></tr>`).join('')||'<tr><td colspan=7>No findings in this category.</td></tr>'}}</tbody></table>`}}
function classifiedSecretFindings(events){{const records=secretRecords(events),content=records.filter(x=>x.scope==='content'),runtime=records.filter(x=>x.scope==='runtime');return `<div class="panel secret-panel"><h2>User / Content Secret Exposure · ${{content.length}}</h2><div class=secret-note>Unique redacted values found in user prompts, assistant responses, or conversation content. Repeated evidence events are correlated below.</div>${{secretRowsTable(content)}}</div><div class=panel><h2>Agent / Runtime Credentials · ${{runtime.length}}</h2><div class=secret-note>Internal service credentials and session cookies retained for forensic completeness. These were not supplied in user prompts and are excluded from the overview exposure count.</div>${{secretRowsTable(runtime)}}</div>`}}
function projectsTable(projects){{return `<div class=panel><h2>User Projects</h2><table><thead><tr><th>Project root</th><th>References</th><th>Unique paths</th><th>Characteristics</th></tr></thead><tbody>${{projects.map(p=>{{const flags=[p.has_git?'Git repository':'',p.has_agent_workspace?'Agent workspace':'',p.has_visualizations?'Visualization cache':''].filter(Boolean).join(', ');return `<tr><td>${{esc(p.project_root)}}</td><td>${{p.references}}</td><td>${{p.unique_paths}}</td><td>${{esc(flags||'Project/workspace')}}</td></tr>`}}).join('')||'<tr><td colspan=4>No project roots detected</td></tr>'}}</tbody></table></div>`}}
function interestingPathsTable(rows){{return `<div class=panel><h2>Interesting Filesystem Paths</h2><table><thead><tr><th>Score</th><th>Category</th><th>Path</th><th>References</th></tr></thead><tbody>${{rows.map(r=>`<tr><td>${{'★'.repeat(r.interest_score)}}</td><td>${{esc(r.category)}}</td><td>${{esc(r.path)}}</td><td>${{r.count}}</td></tr>`).join('')||'<tr><td colspan=4>No validated paths</td></tr>'}}</tbody></table></div>`}}
function categorizedPathPanels(obj){{return Object.entries(obj).map(([category,items])=>kv(category,items)).join('')}}
analyticsBody.innerHTML=classifiedSecretFindings(EVENTS)+projectsTable(STATS.user_projects)+interestingPathsTable(STATS.interesting_paths)+categorizedPathPanels(STATS.categorized_paths)+kv('URLs',STATS.urls)+kv('Domains',STATS.domains)+kv('API Endpoints',STATS.api_endpoints)+kv('Declared Workspace / Permission Paths',STATS.declared_paths)+kv('Models',STATS.models)+kv('Tools',STATS.tools)+kv('Working directories',STATS.working_directories)+kv('Git operations',STATS.git_operations);
diagRows.innerHTML=DIAGS.map(x=>`<tr><td>${{esc(x.file)}}</td><td>${{esc(x.status)}}</td><td>${{esc(x.detail)}}</td></tr>`).join('');
renderReplay();renderEvents();renderIOCs();renderGraph();
</script></body></html>"""


def write_outputs(output: Path, events: list[dict[str, Any]], replay: list[dict[str, Any]], iocs: list[dict[str, Any]], stats: dict[str, Any], diagnostics: list[dict[str, str]]) -> None:
    output.mkdir(parents=True, exist_ok=True)

    safe_events = [redact_event_for_output(event) for event in events]
    safe_replay = []
    for item in replay:
        safe_item = dict(item)
        safe_item["message"], findings = redact_secrets(
            normalize_replay_message(str(item.get("message", "")))
        )
        if findings:
            safe_item["secret_findings"] = findings
        safe_replay.append(safe_item)

    safe_iocs = []
    for item in iocs:
        safe_item = dict(item)
        safe_item["value"], findings = redact_secrets(str(item.get("value", "")))
        if findings:
            safe_item["redacted"] = True
        safe_iocs.append(safe_item)
    event_fields = [
        "event_number", "timestamp_utc", "delta_seconds", "agent", "event_type",
        "category", "action", "summary", "username", "hostname", "session_key",
        "correlation_key", "session_id", "turn_id", "call_id", "process_id",
        "tool_name", "model_detected", "input_tokens", "output_tokens", "reasoning",
        "working_directory", "target", "paths", "path_records", "urls", "domains", "api_endpoints", "commands", "git_operations",
        "secret_findings", "text", "details", "source_type", "source_file",
        "source_line", "evidence_hash", "metadata",
    ]
    write_csv(safe_events, output / "AI_Agent_Timeline.csv", event_fields)
    with (output / "AI_Agent_Timeline.jsonl").open("w", encoding="utf-8") as handle:
        for event in safe_events:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
    write_csv(safe_replay, output / "Case_Replay.csv", [
        "timestamp_utc", "event_number", "session_key", "agent", "role",
        "event_type", "message",
    ])
    write_csv(safe_iocs, output / "Indicators.csv", [
        "type", "value", "first_seen", "last_seen", "count", "agents", "source_events",
    ])
    write_stix(safe_iocs, output / "Indicators_STIX_2.1.json")
    (output / "Analytics.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
    write_csv(diagnostics, output / "Ingestion_Diagnostics.csv", ["file", "status", "detail"])
    (output / "AI_Agent_DFIR_Report.html").write_text(
        render_dashboard(safe_events, safe_replay, safe_iocs, stats, diagnostics), encoding="utf-8"
    )
    hashes = []
    for path in sorted(output.iterdir()):
        if path.is_file() and path.name != "SHA256SUMS.txt":
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            hashes.append(f"{digest}  {path.name}")
    (output / "SHA256SUMS.txt").write_text("\n".join(hashes) + "\n", encoding="utf-8")


def run_analyze(args: argparse.Namespace) -> int:
    input_paths = [Path(p).expanduser().resolve() for p in args.inputs]
    raw_events, diagnostics = ingest(input_paths)
    for external in args.external_csv or []:
        path = Path(external).expanduser().resolve()
        try:
            imported = import_external_csv(path)
            raw_events.extend(imported)
            diagnostics.append({"file": str(path), "status": "parsed", "detail": f"external_csv: {len(imported)} events"})
        except Exception as exc:
            diagnostics.append({"file": str(path), "status": "parse-error", "detail": f"external_csv: {exc}"})
    if not raw_events:
        print("ERROR: No events were parsed. Review Ingestion_Diagnostics or supported formats.", file=sys.stderr)
        # Still produce diagnostics where requested.
        output = Path(args.output).resolve()
        output.mkdir(parents=True, exist_ok=True)
        write_csv(diagnostics, output / "Ingestion_Diagnostics.csv", ["file", "status", "detail"])
        return 2
    if not args.keep_duplicates:
        raw_events = deduplicate(raw_events, args.dedupe_window)
    enriched = [enrich_event(event) for event in raw_events]
    add_event_numbers(enriched)
    iocs = extract_iocs(enriched)
    replay = build_replay(enriched)
    stats = analytics(enriched, iocs)
    output = Path(args.output).expanduser().resolve()
    write_outputs(output, enriched, replay, iocs, stats, diagnostics)
    print(f"EVENTS={len(enriched)}")
    print(f"SESSIONS={stats['sessions']}")
    print(f"IOCS={len(iocs)}")
    print(f"REPORT={output / 'AI_Agent_DFIR_Report.html'}")
    return 0



def write_zip_member_safe(
    zf: zipfile.ZipFile,
    path: Path,
    arcname: Path | str,
) -> None:
    """
    Add a file to a ZIP archive while tolerating filesystem timestamps that
    predate the ZIP format's 1980 lower bound.

    The file contents are preserved exactly. Only the timestamp stored in the
    ZIP entry is clamped when necessary.
    """
    arcname_str = str(arcname).replace("\\", "/")
    stat = path.stat()
    local_time = time.localtime(stat.st_mtime)

    if local_time.tm_year >= 1980:
        zf.write(path, arcname_str)
        return

    info = zipfile.ZipInfo(
        filename=arcname_str,
        date_time=(1980, 1, 1, 0, 0, 0),
    )
    info.compress_type = zf.compression
    info.external_attr = (stat.st_mode & 0xFFFF) << 16

    with path.open("rb") as handle:
        zf.writestr(info, handle.read())


def run_collect(args: argparse.Namespace) -> int:
    # Lightweight cross-platform acquisition. Copies only likely AI-agent artifacts.
    output = Path(args.output).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    home = Path.home()
    candidates = {
        "codex": [home / ".codex"],
        "claude": [home / ".claude"],
        "gemini": [home / ".gemini"],
        "cursor": [home / ".cursor", home / "AppData/Roaming/Cursor", home / "Library/Application Support/Cursor", home / ".config/Cursor"],
        "windsurf": [home / ".windsurf", home / "AppData/Roaming/Windsurf", home / "Library/Application Support/Windsurf", home / ".config/Windsurf"],
        "continue": [home / ".continue"],
        "aider": [home / ".aider.conf.yml", home / ".aider.chat.history.md", home / ".aider.input.history"],
    }
    manifest = []
    for agent, roots in candidates.items():
        for candidate in roots:
            if not candidate.exists():
                continue
            if candidate.is_file():
                files = [candidate]
            else:
                files = [p for p in candidate.rglob("*") if p.is_file()]
            for source in files:
                try:
                    rel = source.relative_to(home)
                except ValueError:
                    rel = Path(source.name)
                destination = output / "raw" / agent / rel
                destination.parent.mkdir(parents=True, exist_ok=True)
                try:
                    shutil.copy2(source, destination)
                    manifest.append({
                        "agent": agent, "source": str(source), "destination": str(destination),
                        "size": source.stat().st_size, "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                    })
                except (OSError, PermissionError) as exc:
                    manifest.append({"agent": agent, "source": str(source), "error": str(exc)})
    write_csv(manifest, output / "Collection_Manifest.csv", ["agent", "source", "destination", "size", "sha256", "error"])
    archive = output.with_suffix(".zip")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in output.rglob("*"):
            if path.is_file():
                write_zip_member_safe(zf, path, path.relative_to(output))
    print(f"FILES={sum(1 for x in manifest if 'error' not in x)}")
    print(f"OUTPUT={output}")
    print(f"ARCHIVE={archive}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aia_dfir", description="AI Agent DFIR collection and investigation framework")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="Parse artifacts and build an investigation package")
    analyze.add_argument("inputs", nargs="+", help="Artifact directories, files, or collector ZIPs")
    analyze.add_argument("-o", "--output", default="AI_Agent_DFIR_Output", help="Output directory")
    analyze.add_argument("--external-csv", action="append", help="Import correlated EDR/SIEM/timeline CSV")
    analyze.add_argument("--keep-duplicates", action="store_true", help="Disable near-duplicate suppression")
    analyze.add_argument("--dedupe-window", type=float, default=2.0, help="Duplicate time window in seconds")
    analyze.set_defaults(func=run_analyze)
    collect = sub.add_parser("collect", help="Cross-platform best-effort local artifact collection")
    collect.add_argument("-o", "--output", default="AI_Agent_Artifacts", help="Collection output directory")
    collect.set_defaults(func=run_collect)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
