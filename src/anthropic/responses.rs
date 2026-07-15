//! OpenAI Responses 兼容端点
//!
//! 把 OpenAI `POST /v1/responses` 请求翻译成内部的 Anthropic
//! [`MessagesRequest`]，复用 [`super::handlers::post_messages`] 的完整链路，
//! 再把 Anthropic 响应翻译回 Responses 格式。
//!
//! 为什么需要这个端点：Codex CLI 自 0.122 起移除了 `wire_api = "chat"`，
//! 只支持 `wire_api = "responses"`——即向 `<base_url>/responses` POST，
//! 走 OpenAI 的 Responses API 协议。因此 `chat/completions` 端点对 Codex
//! 无效，必须提供 Responses 端点。
//!
//! 说明：内部调用始终以非流式方式执行，`stream: true` 的请求在拿到完整结果后
//! 合成为 Responses 的 SSE 事件序列（response.created / output_item /
//! output_text.delta / function_call_arguments / response.completed）。

use axum::{
    Json,
    body::{Body, to_bytes},
    extract::{Extension, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::handlers::post_messages;
use super::middleware::{AppState, KeyContext};
use super::openai::{
    ParsedResponse, collect_text_strings, now_ts, parse_anthropic_message, push_merged,
};
use super::types::{Message, MessagesRequest, OutputConfig, SystemMessage, Tool};

/// 读取内部响应体时的上限（64MB，与请求体上限对齐）
const MAX_INNER_BODY: usize = 64 * 1024 * 1024;

/// 未显式给出 max_output_tokens 时的默认输出上限
const DEFAULT_MAX_TOKENS: i32 = 32000;

// ============================ 请求类型 ============================

#[derive(Debug, Deserialize)]
pub struct ResponsesRequest {
    pub model: String,
    #[serde(default)]
    pub instructions: Option<String>,
    /// 可以是字符串或 input item 数组
    #[serde(default)]
    pub input: Value,
    #[serde(default)]
    pub stream: bool,
    #[serde(default)]
    pub max_output_tokens: Option<i32>,
    /// Accepted from codex but intentionally not forwarded to the Kiro model
    /// (we serve web_search internally and never proxy codex's own tools).
    #[serde(default)]
    #[allow(dead_code)]
    pub tools: Option<Vec<Value>>,
    #[serde(default)]
    pub tool_choice: Option<Value>,
    #[serde(default)]
    pub reasoning: Option<ReasoningConfig>,
}

#[derive(Debug, Deserialize)]
pub struct ReasoningConfig {
    #[serde(default)]
    pub effort: Option<String>,
}

// ============================ Handler ============================

/// `POST /v1/responses`
pub async fn post_responses(
    State(state): State<AppState>,
    Extension(key_ctx): Extension<KeyContext>,
    Json(req): Json<ResponsesRequest>,
) -> Response {
    let want_stream = req.stream;
    let model = req.model.clone();

    tracing::info!(
        model = %model,
        stream = %want_stream,
        "Received POST /v1/responses request"
    );

    // 1. Responses -> Anthropic 请求翻译
    let anthropic_req = match responses_to_anthropic(req) {
        Ok(r) => r,
        Err(msg) => {
            return responses_error(StatusCode::BAD_REQUEST, "invalid_request_error", &msg);
        }
    };

    // 2. 复用 Anthropic 全链路（内部强制非流式）
    let inner = post_messages(State(state), Extension(key_ctx), Json(anthropic_req)).await;

    let status = inner.status();
    let body_bytes = match to_bytes(inner.into_body(), MAX_INNER_BODY).await {
        Ok(b) => b,
        Err(e) => {
            return responses_error(
                StatusCode::BAD_GATEWAY,
                "api_error",
                &format!("failed to read upstream response: {e}"),
            );
        }
    };

    // 上游非 2xx：原样透传
    if !status.is_success() {
        return Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body_bytes))
            .unwrap();
    }

    let anthropic: Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            return responses_error(
                StatusCode::BAD_GATEWAY,
                "api_error",
                &format!("failed to parse upstream response: {e}"),
            );
        }
    };

    // 3. Anthropic -> Responses 响应翻译
    let parsed = parse_anthropic_message(&anthropic, &model);

    if want_stream {
        let sse = build_responses_sse(&parsed);
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/event-stream")
            .header(header::CACHE_CONTROL, "no-cache")
            .body(Body::from(sse))
            .unwrap()
    } else {
        let body = build_responses_object(&parsed);
        (StatusCode::OK, Json(body)).into_response()
    }
}

// ============================ 请求翻译 ============================

fn responses_to_anthropic(req: ResponsesRequest) -> Result<MessagesRequest, String> {
    let max_tokens = req
        .max_output_tokens
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_MAX_TOKENS);

    let mut system: Vec<SystemMessage> = Vec::new();
    if let Some(instr) = req.instructions.as_ref() {
        if !instr.trim().is_empty() {
            system.push(SystemMessage {
                text: instr.clone(),
                cache_control: None,
            });
        }
    }

    let mut merged: Vec<(String, Vec<Value>)> = Vec::new();

    match &req.input {
        // input 直接是字符串 → 单条 user 文本
        Value::String(s) => {
            if !s.is_empty() {
                push_merged(&mut merged, "user", vec![json!({"type":"text","text":s})]);
            }
        }
        Value::Array(items) => {
            for item in items {
                let item_type = item.get("type").and_then(|v| v.as_str());
                let item_role = item.get("role").and_then(|v| v.as_str());

                // Skip codex's tool declarations and system scaffolding. We deliberately
                // do NOT forward codex's real tools (exec/shell/apply_patch) to the Kiro
                // model: their call/result round-trip can't be bridged through this
                // stateless Responses translator, and letting the model invoke them
                // makes codex reject the payload ("tool exec invoked with incompatible
                // payload"). Web search is served internally, so the model needs no
                // codex tools to answer time-sensitive questions.
                if item_type == Some("additional_tools") || item_role == Some("developer") {
                    continue;
                }

                translate_input_item(item, &mut system, &mut merged);
            }
        }
        _ => {}
    }

    let messages: Vec<Message> = merged
        .into_iter()
        .filter(|(_, blocks)| !blocks.is_empty())
        .map(|(role, blocks)| Message {
            role,
            content: Value::Array(blocks),
        })
        .collect();

    if messages.is_empty() {
        return Err("input must contain at least one user/assistant message".to_string());
    }

    // Give the model exactly two tools: a harmless placeholder plus the native
    // web_search. The placeholder guarantees tool_count > 1, which routes kiro-rs
    // to the model-driven web_search agentic loop (the model chooses the query from
    // full context) rather than the naive single-tool fast path (which would grab
    // the first message's text — often codex scaffolding — as the query). We never
    // forward codex's own tools here (see input loop above).
    let tool_list: Vec<Tool> = vec![
        Tool {
            tool_type: None,
            name: "noop".to_string(),
            description: "Placeholder tool; never call this.".to_string(),
            input_schema: Default::default(),
            max_uses: None,
            cache_control: None,
        },
        Tool {
            tool_type: Some("web_search_20250305".to_string()),
            name: "web_search".to_string(),
            description: String::new(),
            input_schema: Default::default(),
            max_uses: Some(5),
            cache_control: None,
        },
    ];
    // Nudge the model to search for time-sensitive queries instead of stale training data.
    system.push(SystemMessage {
        text: "You have a web_search tool that returns live results. For anything \
time-sensitive — current events, news, recent sports results, prices, releases, or facts \
that may be newer than your training data — call web_search before answering, and never \
claim something did not happen without searching first. Do not call any other tool."
            .to_string(),
        cache_control: None,
    });
    let tools = Some(tool_list);
    let tool_choice = req.tool_choice.as_ref().and_then(convert_tool_choice);
    let output_config = req
        .reasoning
        .and_then(|r| r.effort)
        .filter(|e| !e.trim().is_empty())
        .map(|effort| OutputConfig { effort });

    Ok(MessagesRequest {
        model: req.model,
        max_tokens,
        messages,
        stream: false,
        system: if system.is_empty() { None } else { Some(system) },
        tools,
        tool_choice,
        thinking: None,
        output_config,
        metadata: None,
    })
}

/// 翻译单个 Responses input item 到 Anthropic 结构
fn translate_input_item(
    item: &Value,
    system: &mut Vec<SystemMessage>,
    merged: &mut Vec<(String, Vec<Value>)>,
) {
    let ty = item.get("type").and_then(|v| v.as_str()).unwrap_or("");

    match ty {
        // 助手发起的工具调用
        "function_call" => {
            let call_id = item
                .get("call_id")
                .or_else(|| item.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let name = item
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let args_str = item
                .get("arguments")
                .and_then(|v| v.as_str())
                .unwrap_or("{}");
            let input: Value = serde_json::from_str(args_str).unwrap_or_else(|_| json!({}));
            let block = json!({
                "type": "tool_use",
                "id": call_id,
                "name": name,
                "input": input,
            });
            push_merged(merged, "assistant", vec![block]);
        }
        // 工具执行结果 → Anthropic 里属于 user 轮
        "function_call_output" => {
            let call_id = item
                .get("call_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let content = stringify_output(item.get("output"));
            let block = json!({
                "type": "tool_result",
                "tool_use_id": call_id,
                "content": content,
            });
            push_merged(merged, "user", vec![block]);
        }
        // 推理项对 Anthropic 请求无意义，忽略
        "reasoning" => {}
        // "message" 或未标注 type 但带 role 的项
        _ => {
            let role = item.get("role").and_then(|v| v.as_str());
            let Some(role) = role else {
                return;
            };
            match role {
                "system" | "developer" => {
                    for text in collect_content_text(item.get("content")) {
                        system.push(SystemMessage {
                            text,
                            cache_control: None,
                        });
                    }
                }
                "user" | "assistant" => {
                    let blocks = content_blocks(item.get("content"));
                    push_merged(merged, role, blocks);
                }
                _ => {}
            }
        }
    }
}

/// 把 Responses message.content（字符串或数组）转成 Anthropic content blocks
fn content_blocks(content: Option<&Value>) -> Vec<Value> {
    let mut out = Vec::new();
    match content {
        Some(Value::String(s)) => {
            if !s.is_empty() {
                out.push(json!({"type":"text","text":s}));
            }
        }
        Some(Value::Array(parts)) => {
            for part in parts {
                let ty = part.get("type").and_then(|v| v.as_str()).unwrap_or("");
                match ty {
                    "input_text" | "output_text" | "text" => {
                        if let Some(t) = part.get("text").and_then(|v| v.as_str()) {
                            if !t.is_empty() {
                                out.push(json!({"type":"text","text":t}));
                            }
                        }
                    }
                    "input_image" => {
                        // Responses: image_url 是字符串（可能是 data: URL）
                        if let Some(block) = image_block(part) {
                            out.push(block);
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    out
}

/// 仅收集纯文本（system 内容用）
fn collect_content_text(content: Option<&Value>) -> Vec<String> {
    match content {
        Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
        Some(Value::Array(_)) => collect_text_strings(content),
        _ => Vec::new(),
    }
}

/// Responses input_image（仅支持 data: URL）转 Anthropic image block
fn image_block(part: &Value) -> Option<Value> {
    let url = part.get("image_url").and_then(|v| v.as_str())?;
    let rest = url.strip_prefix("data:")?;
    let (media_type, data) = rest.split_once(";base64,")?;
    Some(json!({
        "type": "image",
        "source": {
            "type": "base64",
            "media_type": media_type,
            "data": data,
        }
    }))
}

/// function_call_output.output 归一化为字符串
fn stringify_output(output: Option<&Value>) -> String {
    match output {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(_)) => collect_text_strings(output).join("\n"),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

fn convert_tool_choice(tc: &Value) -> Option<Value> {
    match tc {
        Value::String(s) => match s.as_str() {
            "auto" => Some(json!({"type":"auto"})),
            "required" => Some(json!({"type":"any"})),
            "none" => None,
            _ => Some(json!({"type":"auto"})),
        },
        Value::Object(_) => {
            // Responses: {"type":"function","name":"..."}
            let name = tc
                .get("name")
                .or_else(|| tc.get("function").and_then(|f| f.get("name")))
                .and_then(|v| v.as_str());
            name.map(|n| json!({"type":"tool","name":n}))
        }
        _ => None,
    }
}

// ============================ 响应翻译 ============================

fn new_resp_id() -> String {
    format!("resp_{}", Uuid::new_v4().to_string().replace('-', ""))
}
fn new_msg_id() -> String {
    format!("msg_{}", Uuid::new_v4().to_string().replace('-', ""))
}
fn new_fc_id() -> String {
    format!("fc_{}", Uuid::new_v4().to_string().replace('-', ""))
}

/// 从 ParsedResponse 计算 (status, output items, usage)
struct ResponsesView {
    status: String,
    output: Vec<Value>,
    msg_id: Option<String>,
    usage: Value,
}

fn build_view(p: &ParsedResponse) -> ResponsesView {
    let status = if p.finish_reason == "length" {
        "incomplete".to_string()
    } else {
        "completed".to_string()
    };

    let mut output = Vec::new();
    let mut msg_id = None;

    if !p.text.is_empty() {
        let id = new_msg_id();
        output.push(json!({
            "type": "message",
            "id": id,
            "status": "completed",
            "role": "assistant",
            "content": [{
                "type": "output_text",
                "text": p.text,
                "annotations": [],
            }],
        }));
        msg_id = Some(id);
    }

    for tc in &p.tool_calls {
        let call_id = tc
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let func = tc.get("function");
        let name = func
            .and_then(|f| f.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let arguments = func
            .and_then(|f| f.get("arguments"))
            .and_then(|v| v.as_str())
            .unwrap_or("{}")
            .to_string();
        output.push(json!({
            "type": "function_call",
            "id": new_fc_id(),
            "call_id": call_id,
            "name": name,
            "arguments": arguments,
            "status": "completed",
        }));
    }

    let usage = json!({
        "input_tokens": p.prompt_tokens,
        "input_tokens_details": { "cached_tokens": 0 },
        "output_tokens": p.completion_tokens,
        "output_tokens_details": { "reasoning_tokens": 0 },
        "total_tokens": p.prompt_tokens + p.completion_tokens,
    });

    ResponsesView {
        status,
        output,
        msg_id,
        usage,
    }
}

fn build_response_object_from(p: &ParsedResponse, view: &ResponsesView, id: &str) -> Value {
    let mut obj = json!({
        "id": id,
        "object": "response",
        "created_at": now_ts(),
        "status": view.status,
        "model": p.model,
        "output": view.output,
        "usage": view.usage,
        "parallel_tool_calls": true,
        "tool_choice": "auto",
        "tools": [],
    });
    if view.status == "incomplete" {
        obj["incomplete_details"] = json!({ "reason": "max_output_tokens" });
    }
    obj
}

fn build_responses_object(p: &ParsedResponse) -> Value {
    let view = build_view(p);
    let id = new_resp_id();
    build_response_object_from(p, &view, &id)
}

/// 把完整结果合成为 Responses SSE 事件序列
fn build_responses_sse(p: &ParsedResponse) -> String {
    let view = build_view(p);
    let resp_id = new_resp_id();
    let mut out = String::new();
    let mut seq: i64 = 0;

    let mut emit = |ty: &str, mut payload: Value, seq: &mut i64| {
        payload["type"] = json!(ty);
        payload["sequence_number"] = json!(*seq);
        *seq += 1;
        out.push_str("event: ");
        out.push_str(ty);
        out.push_str("\ndata: ");
        out.push_str(&payload.to_string());
        out.push_str("\n\n");
    };

    // response.created + in_progress
    let created_response = json!({
        "id": resp_id,
        "object": "response",
        "created_at": now_ts(),
        "status": "in_progress",
        "model": p.model,
        "output": [],
    });
    emit(
        "response.created",
        json!({ "response": created_response.clone() }),
        &mut seq,
    );
    emit(
        "response.in_progress",
        json!({ "response": created_response }),
        &mut seq,
    );

    let mut output_index: i64 = 0;

    // 文本消息项
    if !p.text.is_empty() {
        let msg_id = view.msg_id.clone().unwrap_or_else(new_msg_id);
        let mid = msg_id.as_str();
        let msg_added = json!({
            "type": "message",
            "id": mid,
            "status": "in_progress",
            "role": "assistant",
            "content": [],
        });
        emit(
            "response.output_item.added",
            json!({ "output_index": output_index, "item": msg_added }),
            &mut seq,
        );
        emit(
            "response.content_part.added",
            json!({
                "item_id": mid,
                "output_index": output_index,
                "content_index": 0,
                "part": { "type": "output_text", "text": "", "annotations": [] },
            }),
            &mut seq,
        );
        emit(
            "response.output_text.delta",
            json!({
                "item_id": mid,
                "output_index": output_index,
                "content_index": 0,
                "delta": p.text.as_str(),
            }),
            &mut seq,
        );
        emit(
            "response.output_text.done",
            json!({
                "item_id": mid,
                "output_index": output_index,
                "content_index": 0,
                "text": p.text.as_str(),
            }),
            &mut seq,
        );
        emit(
            "response.content_part.done",
            json!({
                "item_id": mid,
                "output_index": output_index,
                "content_index": 0,
                "part": { "type": "output_text", "text": p.text.as_str(), "annotations": [] },
            }),
            &mut seq,
        );
        // 完整 message item（取 view.output 里第一个）
        let done_item = view
            .output
            .first()
            .cloned()
            .unwrap_or_else(|| json!({"type":"message","id":mid,"role":"assistant"}));
        emit(
            "response.output_item.done",
            json!({ "output_index": output_index, "item": done_item }),
            &mut seq,
        );
        output_index += 1;
    }

    // 工具调用项
    let fc_start = if p.text.is_empty() { 0 } else { 1 };
    for fc_item in view.output.iter().skip(fc_start) {
        let item_id = fc_item
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let arguments = fc_item
            .get("arguments")
            .and_then(|v| v.as_str())
            .unwrap_or("{}")
            .to_string();

        let mut added = fc_item.clone();
        added["status"] = json!("in_progress");
        added["arguments"] = json!("");
        emit(
            "response.output_item.added",
            json!({ "output_index": output_index, "item": added }),
            &mut seq,
        );
        emit(
            "response.function_call_arguments.delta",
            json!({
                "item_id": item_id.as_str(),
                "output_index": output_index,
                "delta": arguments.as_str(),
            }),
            &mut seq,
        );
        emit(
            "response.function_call_arguments.done",
            json!({
                "item_id": item_id.as_str(),
                "output_index": output_index,
                "arguments": arguments.as_str(),
            }),
            &mut seq,
        );
        emit(
            "response.output_item.done",
            json!({ "output_index": output_index, "item": fc_item.clone() }),
            &mut seq,
        );
        output_index += 1;
    }

    // response.completed（完整对象含 usage）
    let final_obj = build_response_object_from(p, &view, &resp_id);
    let completed_event = if view.status == "incomplete" {
        "response.incomplete"
    } else {
        "response.completed"
    };
    emit(completed_event, json!({ "response": final_obj }), &mut seq);

    out
}

fn responses_error(status: StatusCode, err_type: &str, message: &str) -> Response {
    let body = json!({
        "error": {
            "message": message,
            "type": err_type,
        }
    });
    (status, Json(body)).into_response()
}
