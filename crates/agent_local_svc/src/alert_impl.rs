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
        _: Request<AlertFilter>,
    ) -> Result<Response<Self::SubscribeAlertsStream>, Status> {
        // TODO: capture alerts from reporter's log_worker channel
        // For now, keep the stream alive with no events
        let (_tx, rx) = mpsc::channel::<Result<AlertEvent, Status>>(64);
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}
