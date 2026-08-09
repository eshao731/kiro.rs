//! Invalid-state errors returned inside a normal Kiro event stream.

use serde::Deserialize;

use crate::kiro::parser::error::ParseResult;
use crate::kiro::parser::frame::Frame;

use super::base::EventPayload;

/// An upstream semantic failure emitted as `invalidStateEvent`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvalidStateEvent {
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub message: String,
}

impl EventPayload for InvalidStateEvent {
    fn from_frame(frame: &Frame) -> ParseResult<Self> {
        frame.payload_as_json()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_reason_and_message() {
        let event: InvalidStateEvent =
            serde_json::from_str(r#"{"reason":"INVALID_STATE","message":"try again"}"#)
                .unwrap();
        assert_eq!(event.reason, "INVALID_STATE");
        assert_eq!(event.message, "try again");
    }
}
