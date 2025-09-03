use rand::RngCore;

/// Represents a tracing context shared between incoming and outgoing requests.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TraceContext {
    pub trace_id: String,
    pub span_id: String,
    pub sampled: bool,
}

/// Indicates which header variant carried the trace context.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TraceHeader {
    TraceParent,
    B3,
    Both,
}

fn gen_hex_16() -> String {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 8];
    rng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn gen_hex_32() -> String {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Generate a new trace context with random identifiers.
pub fn generate_context() -> TraceContext {
    TraceContext {
        trace_id: gen_hex_32(),
        span_id: gen_hex_16(),
        sampled: true,
    }
}

/// Parse a `traceparent` header into a [`TraceContext`].
pub fn parse_traceparent(s: &str) -> Option<TraceContext> {
    // Expected format: "00-<trace-id>-<span-id>-<flags>"
    let mut parts = s.split('-');
    let _version = parts.next()?; // ignored for now
    let trace_id = parts.next()?.to_owned();
    if trace_id.len() != 32 {
        return None;
    }
    let span_id = parts.next()?.to_owned();
    if span_id.len() != 16 {
        return None;
    }
    let flags = parts.next()?;
    let sampled = flags.len() == 2 && &flags[1..] == "1";
    Some(TraceContext {
        trace_id,
        span_id,
        sampled,
    })
}

/// Format a [`TraceContext`] into a `traceparent` header.
pub fn format_traceparent(ctx: &TraceContext) -> String {
    let flag = if ctx.sampled { "01" } else { "00" };
    format!("00-{}-{}-{}", ctx.trace_id, ctx.span_id, flag)
}

/// Parse a b3 single header (traceId-spanId-sampled)
pub fn parse_b3(s: &str) -> Option<TraceContext> {
    let mut parts = s.split('-');
    let trace_id = parts.next()?.to_owned();
    if trace_id.len() != 32 && trace_id.len() != 16 {
        return None;
    }
    let span_id = parts.next()?.to_owned();
    if span_id.len() != 16 {
        return None;
    }
    let sampled = matches!(parts.next(), Some("1" | "d"));
    Some(TraceContext {
        trace_id,
        span_id,
        sampled,
    })
}

/// Format a [`TraceContext`] into a b3 single header.
pub fn format_b3(ctx: &TraceContext) -> String {
    let flag = if ctx.sampled { "1" } else { "0" };
    format!("{}-{}-{}", ctx.trace_id, ctx.span_id, flag)
}

/// Extract trace context from headers represented as `Option<&str>` pairs.
/// Returns the context and which header type was used.
pub fn extract_context(tp: Option<&str>, b3: Option<&str>) -> (TraceContext, TraceHeader) {
    if let Some(val) = tp {
        if let Some(ctx) = parse_traceparent(val) {
            return (ctx, TraceHeader::TraceParent);
        }
    }
    if let Some(val) = b3 {
        if let Some(ctx) = parse_b3(val) {
            return (ctx, TraceHeader::B3);
        }
    }
    (generate_context(), TraceHeader::Both)
}

/// Insert trace context headers into a mutable header map.
pub fn insert_headers<F>(kind: TraceHeader, ctx: &TraceContext, mut insert: F)
where
    F: FnMut(&str, &str),
{
    match kind {
        TraceHeader::TraceParent => {
            let tp = format_traceparent(ctx);
            insert("traceparent", &tp);
        }
        TraceHeader::B3 => {
            let b3 = format_b3(ctx);
            insert("b3", &b3);
        }
        TraceHeader::Both => {
            let tp = format_traceparent(ctx);
            insert("traceparent", &tp);
            let b3 = format_b3(ctx);
            insert("b3", &b3);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora_http::RequestHeader;

    #[test]
    fn round_trip_traceparent() {
        let ctx = generate_context();
        let header = format_traceparent(&ctx);
        let parsed = parse_traceparent(&header).unwrap();
        assert_eq!(parsed, ctx);
    }

    #[test]
    fn round_trip_b3() {
        let ctx = generate_context();
        let header = format_b3(&ctx);
        let parsed = parse_b3(&header).unwrap();
        assert_eq!(parsed, ctx);
    }

    #[test]
    fn propagation_round_trip() {
        // No headers set -> generate
        let (ctx, _) = extract_context(None, None);
        let mut outbound = RequestHeader::build("GET", b"/", None).unwrap();
        let tp = format_traceparent(&ctx);
        let b3 = format_b3(&ctx);
        outbound.insert_header("traceparent", &tp).unwrap();
        outbound.insert_header("b3", &b3).unwrap();
        let tp_val = outbound
            .headers
            .get("traceparent")
            .and_then(|h| h.to_str().ok())
            .unwrap();
        let parsed = parse_traceparent(tp_val).unwrap();
        assert_eq!(parsed.trace_id, ctx.trace_id);
        let b3_val = outbound
            .headers
            .get("b3")
            .and_then(|h| h.to_str().ok())
            .unwrap();
        let parsed_b3 = parse_b3(b3_val).unwrap();
        assert_eq!(parsed_b3.trace_id, ctx.trace_id);
    }
}
