//! Audit regression test: the public `SignMessageBuffer` must enforce the
//! memory bound its documentation advertises.
//!
//! The type's docs promise "at most MAX_PARTIES entries per round", but that
//! invariant was only enforced upstream by `DilithiumSignProtocol::message`
//! (which filters non-participants before buffering). The standalone public
//! API accepted any caller-supplied `party_id`, so a consumer using the
//! buffer directly for out-of-order network buffering could be driven to
//! store an unbounded number of entries — each potentially megabytes, since
//! legitimate Round 2/3 payloads are that large — by varying `party_id`.

use qp_rusty_crystals_threshold::{
	broadcast::{Round2Broadcast, Round3Broadcast, SSID_SIZE},
	signing_protocol::SignMessageBuffer,
	ParticipantList,
};

/// The protocol-wide maximum party count (MAX_PARTIES in `error.rs`).
const MAX_PARTIES: usize = 6;

#[test]
fn sign_message_buffer_bounds_entries_to_participants() {
	let ssid = [0xB7u8; SSID_SIZE];
	let participants = ParticipantList::new(&[0, 1, 2]).unwrap();
	let mut buffer = SignMessageBuffer::new(participants);

	// A remote peer varies party_id across 1000 broadcasts. A real Round 2
	// payload can be ~9.4 MB; a small stand-in keeps the test fast without
	// changing the counting behavior.
	let payload = vec![0xEEu8; 4096];
	for party_id in 0..1000u32 {
		buffer.buffer_round2(Round2Broadcast::new(ssid, party_id, payload.clone()));
		buffer.buffer_round3(Round3Broadcast::new(ssid, party_id, payload.clone()));
	}

	let round2 = buffer.take_round2();
	let round3 = buffer.take_round3();
	assert!(
		round2.len() <= MAX_PARTIES,
		"documented bound violated: {} Round 2 entries buffered (max {MAX_PARTIES})",
		round2.len()
	);
	assert!(
		round3.len() <= MAX_PARTIES,
		"documented bound violated: {} Round 3 entries buffered (max {MAX_PARTIES})",
		round3.len()
	);

	// Messages from actual session participants are retained, non-members dropped.
	let round2_ids: Vec<u32> = round2.iter().map(|m| m.party_id).collect();
	assert_eq!(round2_ids, vec![0, 1, 2], "participant messages must be kept");
	let round3_ids: Vec<u32> = round3.iter().map(|m| m.party_id).collect();
	assert_eq!(round3_ids, vec![0, 1, 2], "participant messages must be kept");
}
