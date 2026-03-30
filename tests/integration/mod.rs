use sandspy::events::{
	create_event_bus, Event, EventKind, FileCategory, RiskLevel,
};
use std::path::PathBuf;

#[test]
fn event_new_defaults_risk_to_zero() {
	let event = Event::new(EventKind::FileRead {
		path: PathBuf::from(".env"),
		sensitive: true,
		category: FileCategory::Secret,
	});

	assert_eq!(event.risk_score, 0);
}

#[test]
fn event_serializes_to_json() {
	let event = Event::with_risk(
		EventKind::Alert {
			message: "unknown network destination detected".to_string(),
			severity: RiskLevel::High,
		},
		25,
	);

	let json = serde_json::to_string(&event).expect("event should serialize");

	assert!(json.contains("\"timestamp\""));
	assert!(json.contains("\"kind\""));
	assert!(json.contains("\"risk_score\":25"));
	assert!(json.contains("unknown network destination detected"));
}

#[tokio::test]
async fn event_bus_sends_and_receives_events() {
	let (tx, mut rx) = create_event_bus();
	let event = Event::with_risk(
		EventKind::Alert {
			message: "test alert".to_string(),
			severity: RiskLevel::Medium,
		},
		10,
	);

	tx.send(event).await.expect("send should succeed");

	let received = rx.recv().await.expect("event should be received");
	match received.kind {
		EventKind::Alert { message, severity } => {
			assert_eq!(message, "test alert");
			assert_eq!(severity, RiskLevel::Medium);
		}
		other => panic!("unexpected event kind: {other:?}"),
	}
	assert_eq!(received.risk_score, 10);
}
