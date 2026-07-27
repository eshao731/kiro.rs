#!/usr/bin/env python3
"""Probe Kiro's raw generateAssistantResponse API with an existing credential file.

This intentionally does not call kiro.rs HTTP routes. It reads config and
credentials JSON files, constructs the Kiro wire request, and parses the AWS
event-stream response frames enough to count assistantResponseEvent content.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Any

import requests


BUILDER_ID_PROFILE_ARN = "arn:aws:codewhisperer:us-east-1:638616132270:profile/AAAACCCCXXXX"
SOCIAL_PROFILE_ARN = "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK"


def pick(obj: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in obj and obj[name] is not None:
            return obj[name]
    return default


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def normalize_machine_id(value: str | None) -> str | None:
    if not value:
        return None
    trimmed = value.strip()
    if len(trimmed) == 64 and all(c in "0123456789abcdefABCDEF" for c in trimmed):
        return trimmed
    without_dashes = trimmed.replace("-", "")
    if len(without_dashes) == 32 and all(c in "0123456789abcdefABCDEF" for c in without_dashes):
        return without_dashes + without_dashes
    return None


def machine_id_for(cred: dict[str, Any], config: dict[str, Any]) -> str:
    for value in (
        pick(cred, "machineId", "machine_id"),
        pick(config, "machineId", "machine_id"),
    ):
        normalized = normalize_machine_id(value)
        if normalized:
            return normalized

    api_key = pick(cred, "kiroApiKey", "kiro_api_key")
    if is_api_key_credential(cred) and api_key:
        seed = f"KiroAPIKey/{api_key}"
    else:
        refresh_token = pick(cred, "refreshToken", "refresh_token") or ""
        seed = f"KotlinNativeAPI/{refresh_token}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def is_api_key_credential(cred: dict[str, Any]) -> bool:
    auth_method = str(pick(cred, "authMethod", "auth_method", default="")).lower()
    return bool(pick(cred, "kiroApiKey", "kiro_api_key")) or auth_method in {"api_key", "apikey"}


def is_external_idp(cred: dict[str, Any]) -> bool:
    return str(pick(cred, "authMethod", "auth_method", default="")).lower() == "external_idp"


def is_social_login(cred: dict[str, Any]) -> bool:
    auth_method = str(pick(cred, "authMethod", "auth_method", default="")).lower()
    provider = str(pick(cred, "provider", default="")).lower()
    return auth_method == "social" or provider in {"github", "google"}


def streaming_profile_arn(cred: dict[str, Any]) -> str | None:
    if is_api_key_credential(cred):
        return None
    explicit = pick(cred, "profileArn", "profile_arn")
    if explicit:
        return explicit
    return SOCIAL_PROFILE_ARN if is_social_login(cred) else BUILDER_ID_PROFILE_ARN


def region_for(cred: dict[str, Any], config: dict[str, Any]) -> str:
    explicit = pick(cred, "apiRegion", "api_region")
    if explicit:
        return explicit
    profile_arn = pick(cred, "profileArn", "profile_arn")
    if profile_arn and ":codewhisperer:" in profile_arn:
        parts = profile_arn.split(":")
        if len(parts) > 3 and parts[3]:
            return parts[3]
    return pick(config, "apiRegion", "api_region", "region", default="us-east-1")


def credential_token(cred: dict[str, Any]) -> str:
    if is_api_key_credential(cred):
        token = pick(cred, "kiroApiKey", "kiro_api_key")
    else:
        token = pick(cred, "accessToken", "access_token")
    if not token:
        raise ValueError("credential has no usable token")
    return token


def make_body(model_id: str, prompt: str, cred: dict[str, Any], effort: str | None) -> dict[str, Any]:
    conversation_id = str(uuid.uuid4())
    continuation_id = str(uuid.uuid4())
    body = {
        "conversationState": {
            "agentContinuationId": continuation_id,
            "agentTaskType": "vibe",
            "chatTriggerType": "MANUAL",
            "currentMessage": {
                "userInputMessage": {
                    "userInputMessageContext": {
                        "envState": {
                            "operatingSystem": "macos",
                            "currentWorkingDirectory": "/tmp",
                        }
                    },
                    "content": prompt,
                    "modelId": model_id,
                    "origin": "AI_EDITOR",
                }
            },
            "conversationId": conversation_id,
            "history": [],
        }
    }
    profile_arn = streaming_profile_arn(cred)
    if profile_arn:
        body["profileArn"] = profile_arn
    if effort:
        body["additionalModelRequestFields"] = {"output_config": {"effort": effort}}
    return body


def make_headers(cred: dict[str, Any], config: dict[str, Any], endpoint: str, region: str) -> dict[str, str]:
    token = credential_token(cred)
    machine_id = machine_id_for(cred, config)
    kiro_version = pick(config, "kiroVersion", "kiro_version", default="0.11.107")
    system_version = pick(config, "systemVersion", "system_version", default="darwin#24.6.0")
    node_version = pick(config, "nodeVersion", "node_version", default="22.22.0")
    host = f"runtime.{region}.kiro.dev" if endpoint == "runtime" else f"q.{region}.amazonaws.com"

    headers = {
        "content-type": "application/json",
        "Connection": "close",
        "x-amzn-codewhisperer-optout": "true",
        "x-amzn-kiro-agent-mode": "vibe",
        "x-amz-user-agent": f"aws-sdk-js/1.0.34 KiroIDE-{kiro_version}-{machine_id}",
        "user-agent": (
            "aws-sdk-js/1.0.34 ua/2.1 "
            f"os/{system_version} lang/js md/nodejs#{node_version} "
            f"api/codewhispererstreaming#1.0.34 m/E KiroIDE-{kiro_version}-{machine_id}"
        ),
        "host": host,
        "amz-sdk-invocation-id": str(uuid.uuid4()),
        "amz-sdk-request": "attempt=1; max=3",
        "Authorization": f"Bearer {token}",
    }
    if is_api_key_credential(cred):
        headers["tokentype"] = "API_KEY"
    elif is_external_idp(cred):
        headers["tokentype"] = "EXTERNAL_IDP"
    return headers


def endpoint_url(endpoint: str, region: str) -> str:
    if endpoint == "runtime":
        return f"https://runtime.{region}.kiro.dev/generateAssistantResponse"
    if endpoint == "ide":
        return f"https://q.{region}.amazonaws.com/generateAssistantResponse"
    raise ValueError(f"unsupported endpoint: {endpoint}")


def parse_headers(data: bytes) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    offset = 0
    while offset < len(data):
        name_len = data[offset]
        offset += 1
        name = data[offset : offset + name_len].decode("utf-8", "replace")
        offset += name_len
        value_type = data[offset]
        offset += 1
        if value_type in (0, 1):
            value = value_type == 0
        elif value_type == 2:
            value = struct.unpack(">b", data[offset : offset + 1])[0]
            offset += 1
        elif value_type == 3:
            value = struct.unpack(">h", data[offset : offset + 2])[0]
            offset += 2
        elif value_type == 4:
            value = struct.unpack(">i", data[offset : offset + 4])[0]
            offset += 4
        elif value_type in (5, 8):
            value = struct.unpack(">q", data[offset : offset + 8])[0]
            offset += 8
        elif value_type in (6, 7):
            length = struct.unpack(">H", data[offset : offset + 2])[0]
            offset += 2
            raw = data[offset : offset + length]
            offset += length
            value = raw.decode("utf-8", "replace") if value_type == 7 else raw
        elif value_type == 9:
            value = data[offset : offset + 16].hex()
            offset += 16
        else:
            raise ValueError(f"unknown event-stream header type: {value_type}")
        headers[name] = value
    return headers


def pop_frames(buffer: bytearray) -> list[tuple[dict[str, Any], bytes]]:
    frames: list[tuple[dict[str, Any], bytes]] = []
    while True:
        if len(buffer) < 12:
            return frames
        total_length, header_length = struct.unpack(">II", buffer[:8])
        if total_length < 16 or total_length > 24 * 1024 * 1024:
            raise ValueError(f"invalid frame length {total_length}")
        if len(buffer) < total_length:
            return frames
        frame = bytes(buffer[:total_length])
        del buffer[:total_length]
        headers_start = 12
        headers_end = headers_start + header_length
        payload_end = total_length - 4
        headers = parse_headers(frame[headers_start:headers_end])
        payload = frame[headers_end:payload_end]
        frames.append((headers, payload))


@dataclass
class ProbeResult:
    credential_id: Any
    endpoint: str
    region: str
    model_id: str
    status_code: int
    seconds: float
    frames: int
    assistant_events: int
    text_chars: int
    estimated_tokens: int
    context_usage_pct: float | None
    metering_usage: float
    error_events: list[str]
    finish: str
    text_head: str | None = None
    text_tail: str | None = None


def estimate_tokens(text: str) -> int:
    return max(0, len(text) // 4)


def probe_once(
    session: requests.Session,
    cred: dict[str, Any],
    config: dict[str, Any],
    endpoint: str,
    model_id: str,
    prompt: str,
    timeout: int,
    snippets: bool,
    effort: str | None,
) -> ProbeResult:
    region = region_for(cred, config)
    url = endpoint_url(endpoint, region)
    headers = make_headers(cred, config, endpoint, region)
    body = make_body(model_id, prompt, cred, effort)

    start = time.monotonic()
    response = session.post(url, headers=headers, data=json.dumps(body), stream=True, timeout=(30, timeout))
    text_parts: list[str] = []
    frames = 0
    assistant_events = 0
    context_usage_pct: float | None = None
    metering_usage = 0.0
    error_events: list[str] = []

    if response.status_code >= 400:
        sample = response.text[:500].replace("\n", " ")
        return ProbeResult(
            credential_id=pick(cred, "id"),
            endpoint=endpoint,
            region=region,
            model_id=model_id,
            status_code=response.status_code,
            seconds=time.monotonic() - start,
            frames=0,
            assistant_events=0,
            text_chars=0,
            estimated_tokens=0,
            context_usage_pct=None,
            metering_usage=0.0,
            error_events=[sample],
            finish="http_error",
            text_head=None,
            text_tail=None,
        )

    buffer = bytearray()
    finish = "eof"
    try:
        for chunk in response.iter_content(chunk_size=65536):
            if not chunk:
                continue
            buffer.extend(chunk)
            for frame_headers, payload in pop_frames(buffer):
                frames += 1
                event_type = str(frame_headers.get(":event-type", ""))
                message_type = str(frame_headers.get(":message-type", ""))
                if message_type in {"error", "exception"}:
                    error_events.append(f"{message_type}:{event_type}:{payload[:300]!r}")
                    finish = message_type
                    continue
                try:
                    data = json.loads(payload.decode("utf-8"))
                except Exception:
                    data = {}
                if event_type == "assistantResponseEvent":
                    assistant_events += 1
                    content = data.get("content") or ""
                    if content:
                        text_parts.append(content)
                elif event_type == "contextUsageEvent":
                    value = data.get("contextUsagePercentage")
                    if isinstance(value, (int, float)):
                        context_usage_pct = float(value)
                elif event_type == "meteringEvent":
                    value = data.get("usage")
                    if isinstance(value, (int, float)):
                        metering_usage += float(value)
                elif event_type and event_type not in {
                    "toolUseEvent",
                    "reasoningContentEvent",
                }:
                    pass
    except requests.exceptions.ReadTimeout:
        finish = "read_timeout"
    except Exception as exc:
        finish = f"parse_error:{type(exc).__name__}"
        error_events.append(str(exc))
    finally:
        response.close()

    text = "".join(text_parts)
    text_head = text[:500] if snippets else None
    text_tail = text[-500:] if snippets else None
    return ProbeResult(
        credential_id=pick(cred, "id"),
        endpoint=endpoint,
        region=region,
        model_id=model_id,
        status_code=response.status_code,
        seconds=time.monotonic() - start,
        frames=frames,
        assistant_events=assistant_events,
        text_chars=len(text),
        estimated_tokens=estimate_tokens(text),
        context_usage_pct=context_usage_pct,
        metering_usage=metering_usage,
        error_events=error_events,
        finish=finish,
        text_head=text_head,
        text_tail=text_tail,
    )


def load_credentials(path: str) -> list[dict[str, Any]]:
    raw = load_json(path)
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        for key in ("credentials", "items", "entries", "accounts"):
            value = raw.get(key)
            if isinstance(value, list):
                return value
    raise ValueError("unsupported credentials file shape")


def default_prompt() -> str:
    return (
        "Output exactly 1600 numbered lines, no introduction and no summary. "
        "Each line must use this format: "
        "0001 alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi omicron pi rho sigma tau. "
        "Increment the number on every line from 0001 to 1600. "
        "Do not skip lines. Do not stop early. Continue until line 1600 is complete."
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/opt/kiro2api/config.json")
    parser.add_argument("--credentials", default="/opt/kiro2api/credentials.json")
    parser.add_argument("--ids", nargs="+", type=int, default=[])
    parser.add_argument("--models", nargs="+", default=["claude-opus-4.6", "claude-opus-4.8"])
    parser.add_argument("--endpoint", choices=["ide", "runtime"], default="ide")
    parser.add_argument("--timeout", type=int, default=420)
    parser.add_argument("--prompt")
    parser.add_argument("--prompt-file")
    parser.add_argument("--snippets", action="store_true")
    parser.add_argument("--effort", choices=["low", "medium", "high", "max", "xhigh"])
    parser.add_argument("--include-disabled", action="store_true")
    args = parser.parse_args()

    config = load_json(args.config)
    credentials = load_credentials(args.credentials)
    if args.prompt is not None:
        prompt = args.prompt
    elif args.prompt_file:
        prompt = open(args.prompt_file, encoding="utf-8").read()
    else:
        prompt = default_prompt()

    selected = []
    id_set = set(args.ids)
    for cred in credentials:
        cred_id = pick(cred, "id")
        if id_set and cred_id not in id_set:
            continue
        if pick(cred, "disabled", default=False) and not args.include_disabled:
            continue
        selected.append(cred)

    if not selected:
        print("no credentials selected", file=sys.stderr)
        return 2

    print(
        json.dumps(
            {
                "selected_ids": [pick(c, "id") for c in selected],
                "models": args.models,
                "endpoint": args.endpoint,
                "prompt_chars": len(prompt),
            },
            ensure_ascii=True,
        ),
        flush=True,
    )

    session = requests.Session()
    for cred in selected:
        for model_id in args.models:
            try:
                result = probe_once(
                    session,
                    cred,
                    config,
                    args.endpoint,
                    model_id,
                    prompt,
                    args.timeout,
                    args.snippets,
                    args.effort,
                )
                print(json.dumps(result.__dict__, ensure_ascii=True), flush=True)
            except Exception as exc:
                print(
                    json.dumps(
                        {
                            "credential_id": pick(cred, "id"),
                            "endpoint": args.endpoint,
                            "model_id": model_id,
                            "finish": f"probe_exception:{type(exc).__name__}",
                            "error": str(exc),
                        },
                        ensure_ascii=True,
                    ),
                    flush=True,
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
