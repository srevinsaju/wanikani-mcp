use rmcp::ErrorData as McpError;
use serde::de::StdError;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum Error {
    Wabisabi(wanisabi::error::Error),
    Mcp(McpError),
    NotFound(String),
    Internal(String),
    InvalidArgument(String),
}

impl From<wanisabi::error::Error> for Error {
    fn from(e: wanisabi::error::Error) -> Self {
        Error::Wabisabi(e)
    }
}

impl From<McpError> for Error {
    fn from(e: McpError) -> Self {
        Error::Mcp(e)
    }
}
impl From<std::env::VarError> for Error {
    fn from(e: std::env::VarError) -> Self {
        Error::Internal(e.to_string())
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Wabisabi(e) => write!(f, "Wabisabi error: {}", e),
            Error::Mcp(e) => write!(f, "MCP error: {}", e),
            Error::NotFound(message) => write!(f, "Not Found: {}", message),
            Error::Internal(message) => write!(f, "Internal error: {}", message),
            Error::InvalidArgument(message) => write!(f, "Invalid Argument: {}", message),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Wabisabi(_) => None,
            Error::Mcp(e) => Some(e),
            Error::NotFound(_) => None,
            Error::Internal(_) => None,
            Error::InvalidArgument(_) => None,
        }
    }
}

impl From<Error> for McpError {
    fn from(e: Error) -> Self {
        match e {
            Error::Wabisabi(e) => McpError::internal_error(
                "wanikani error",
                Some(serde_json::json!({
                    "reason": e.to_string(),
                })),
            ),
            Error::Mcp(e) => e,
            Error::NotFound(message) => McpError::invalid_request(message, None),
            Error::Internal(message) => McpError::internal_error(message, None),
            Error::InvalidArgument(message) => McpError::invalid_request(message, None),
        }
    }
}
