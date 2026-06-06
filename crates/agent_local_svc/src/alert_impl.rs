use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use grpc_gateway::alert::{alert_service_server::AlertService, AlertEvent, AlertFilter};
use crate::data_hub::AgentDataHub;

type AlertStream = Pin<
    Box<dyn tokio_stream::Stream<Item = Result<AlertEvent, Status>> + Send>,
>;

pub struct AlertServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl AlertService for AlertServiceImpl {
    type SubscribeAlertsStream = AlertStream;

    async fn subscribe_alerts(
        &self,
        request: Request<AlertFilter>,
    ) -> Result<Response<Self::SubscribeAlertsStream>, Status> {
        let filter = request.into_inner();
        let mut broadcast_rx = grpc_gateway::notify::subscribe_alerts();
        let (tx, rx) = mpsc::channel::<Result<AlertEvent, Status>>(256);

        tokio::spawn(async move {
            loop {
                match broadcast_rx.recv().await {
                    Ok(event) => {
                        // Apply filter (0 = ALL)
                        if filter.r#type != 0 && event.r#type != filter.r#type {
                            continue;
                        }
                        if tx.send(Ok(event)).await.is_err() {
                            break; // client disconnected
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        log::warn!("Alert broadcast lagged by {} messages", n);
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}
