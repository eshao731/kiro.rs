//! Code content events returned by the Kiro streaming API.

use serde::Deserialize;

use crate::kiro::parser::error::ParseResult;
use crate::kiro::parser::frame::Frame;

use super::base::EventPayload;

/// A text/code response fragment emitted as `codeEvent`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeEvent {
    #[serde(default)]
    pub content: String,
}

impl EventPayload for CodeEvent {
    fn from_frame(frame: &Frame) -> ParseResult<Self> {
        frame.payload_as_json()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_content() {
        let event: CodeEvent = serde_json::from_str(r#"{"content":"let x = 1;"}"#).unwrap();
        assert_eq!(event.content, "let x = 1;");
    }
}
