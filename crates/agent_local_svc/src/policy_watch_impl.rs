use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use grpc_gateway::policy_watch::{
    policy_watch_service_server::PolicyWatchService, PolicyChangeEvent,
};
use crate::data_hub::AgentDataHub;

type PolicyWatchStream = Pin<
    Box<dyn tokio_stream::Stream<Item = Result<PolicyChangeEvent, Status>> + Send>,
>;

pub struct PolicyWatchServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl PolicyWatchService for PolicyWatchServiceImpl {
    type SubscribePolicyChangesStream = PolicyWatchStream;

    async fn subscribe_policy_changes(
        &self,
        _: Request<grpc_gateway::common::Empty>,
    ) -> Result<Response<Self::SubscribePolicyChangesStream>, Status> {
        let mut broadcast_rx = self.data_hub.subscribe_changes();
        let (tx, rx) = mpsc::channel::<Result<PolicyChangeEvent, Status>>(64);

        tokio::spawn(async move {
            loop {
                match broadcast_rx.recv().await {
                    Ok(change) => {
                        let event = PolicyChangeEvent {
                            r#type: change as i32,
                            timestamp: chrono::Utc::now().timestamp_millis() as u64,
                        };
                        if tx.send(Ok(event)).await.is_err() {
                            break; // client disconnected
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        log::warn!("PolicyChange broadcast lagged by {} messages", n);
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}
