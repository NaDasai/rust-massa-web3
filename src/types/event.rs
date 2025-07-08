use serde::{Deserialize, Serialize};

#[allow(dead_code)] // Temporary solution to avoid compilation warning of unused enum variants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventDetails {
    pub event_id: String,
    pub event_period: u64,
    pub event_thread: u32,
    pub event_index: u64,
    pub operation_id: Option<String>,
    pub event_data: String,
    pub is_failure: bool,
    pub status: i32,
    pub call_stack: Vec<String>,
}

// imlements default for EventDetails
impl Default for EventDetails {
    fn default() -> Self {
        EventDetails {
            event_id: String::new(),
            event_period: 0,
            event_thread: 0,
            event_index: 0,
            operation_id: None,
            event_data: String::new(),
            is_failure: false,
            status: 0,
            call_stack: Vec::new(),
        }
    }
}
