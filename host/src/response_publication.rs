//! Response publication and its retained wake are one host-side operation.
use crate::dispatcher_wake::DispatcherWake;
use enclave_os_common::queue::SpscProducer;
use enclave_os_common::rpc::{self, HonestRpcFrameError, HonestRpcIdentity, RpcRole};

#[derive(Debug)]
pub(super) enum PublishError {
    Encoding(HonestRpcFrameError),
    QueueFull,
}

impl std::fmt::Display for PublishError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encoding(error) => write!(formatter, "invalid response frame: {error:?}"),
            Self::QueueFull => formatter.write_str("response queue saturated"),
        }
    }
}

pub(super) fn publish(
    role: RpcRole,
    queue: &SpscProducer,
    wake: &DispatcherWake,
    identity: HonestRpcIdentity,
    status: i32,
    payload: &[u8],
) -> Result<(), PublishError> {
    let response =
        rpc::encode_honest_response(identity, status, payload).map_err(PublishError::Encoding)?;
    queue
        .try_send(&response)
        .map_err(|_| PublishError::QueueFull)?;
    // Release publication in the ring precedes the retained signal. The
    // consumer must still validate its own exact frame, never this host hint.
    wake.notify_response(role);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclave_os_common::queue::{SpscConsumer, SpscQueueHeader};
    use enclave_os_common::rpc::RpcMethod;
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    fn queue() -> (SpscProducer, SpscConsumer) {
        let header = Box::into_raw(Box::new(SpscQueueHeader::new(4096)));
        let buffer = Box::into_raw(vec![0_u8; 4096].into_boxed_slice()).cast::<u8>();
        // SAFETY: test allocations stay live; one endpoint owns each direction.
        unsafe {
            (
                SpscProducer::from_raw(header, buffer),
                SpscConsumer::from_raw(header, buffer),
            )
        }
    }
    fn identity() -> HonestRpcIdentity {
        HonestRpcIdentity {
            role: RpcRole::Execution,
            node_id: 3,
            node_generation: 8,
            operation_id: 13,
            method: RpcMethod::NetSend,
        }
    }

    #[test]
    fn actual_publication_precedes_retained_hint_and_preserves_exact_frame() {
        let (tx, rx) = queue();
        let wake = DispatcherWake::new();
        publish(
            RpcRole::Execution,
            &tx,
            &wake,
            identity(),
            0,
            b"exact response",
        )
        .unwrap();
        assert_eq!(wake.wait_response(RpcRole::Execution, Duration::ZERO), 0);
        assert_eq!(wake.wait_response(RpcRole::Control, Duration::ZERO), 1);
        let bytes = rx.try_recv().unwrap();
        let frame = rpc::decode_honest_response_for(&bytes, identity()).unwrap();
        assert_eq!(frame.payload, b"exact response");
        assert_eq!(frame.status, 0);
        assert!(rx.try_recv().is_none());
        assert_eq!(wake.wait_response(RpcRole::Execution, Duration::ZERO), 1);
    }

    #[test]
    fn actual_publication_after_empty_read_wakes_and_delivers_the_original_identity() {
        let (tx, rx) = queue();
        assert!(rx.try_recv().is_none());
        let wake = Arc::new(DispatcherWake::new());
        let start = Arc::new(Barrier::new(2));
        let producer = {
            let (wake, start) = (wake.clone(), start.clone());
            std::thread::spawn(move || {
                start.wait();
                publish(RpcRole::Execution, &tx, &wake, identity(), -11, &[]).unwrap();
            })
        };
        start.wait();
        assert_eq!(
            wake.wait_response(RpcRole::Execution, Duration::from_secs(1)),
            0
        );
        let bytes = rx.try_recv().unwrap();
        assert_eq!(
            rpc::decode_honest_response_for(&bytes, identity())
                .unwrap()
                .status,
            -11
        );
        producer.join().unwrap();
    }

    #[test]
    fn rejected_or_saturated_publication_cannot_create_a_completion_hint() {
        let (tx, rx) = queue();
        let wake = DispatcherWake::new();
        assert!(matches!(
            publish(RpcRole::Execution, &tx, &wake, identity(), 0, &[0; 4096]),
            Err(PublishError::QueueFull)
        ));
        assert!(rx.try_recv().is_none());
        assert_eq!(wake.wait_response(RpcRole::Execution, Duration::ZERO), 1);
        let oversized = vec![0; rpc::MAX_HONEST_RPC_PAYLOAD_BYTES + 1];
        assert!(matches!(
            publish(RpcRole::Execution, &tx, &wake, identity(), 0, &oversized),
            Err(PublishError::Encoding(_))
        ));
        assert!(rx.try_recv().is_none());
        assert_eq!(wake.wait_response(RpcRole::Execution, Duration::ZERO), 1);
    }
}
