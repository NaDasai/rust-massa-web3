use anyhow::{Context, Result};
use massa_proto_rs::massa::model::v1::ScExecutionEvent;

use crate::types::event::EventDetails;

// Extract informations from event and returns it as an EventDetails struct
pub fn extract_event_details(event: &ScExecutionEvent) -> Result<EventDetails> {
    let event_context = event.context.as_ref().context("Missing event context")?;
    let origin_slot = event_context
        .origin_slot
        .as_ref()
        .context("Missing event origin slot")?;

    Ok(EventDetails {
        event_id: format!(
            "{}_{}_{}",
            origin_slot.period, origin_slot.thread, event_context.index_in_slot
        ),
        event_period: origin_slot.period,
        event_thread: origin_slot.thread,
        event_index: event_context.index_in_slot,
        operation_id: event_context.origin_operation_id.clone(),
        event_data: String::from_utf8_lossy(&event.data).into_owned(),
        is_failure: event_context.is_failure,
        status: event_context.status,
        call_stack: event_context.call_stack.clone(),
    })
}
