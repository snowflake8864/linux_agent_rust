use tonic::{Request, Response, Status};

use grpc_gateway::token::{token_service_server::TokenService, TokenResponse};
use grpc_gateway::common::Empty;
use crate::get_cached_token;

pub struct TokenServiceImpl;

#[tonic::async_trait]
impl TokenService for TokenServiceImpl {
    async fn get_token(
        &self,
        _: Request<Empty>,
    ) -> Result<Response<TokenResponse>, Status> {
        match get_cached_token() {
            Some(token) => Ok(Response::new(TokenResponse {
                token,
                is_valid: true,
            })),
            None => Ok(Response::new(TokenResponse {
                token: String::new(),
                is_valid: false,
            })),
        }
    }
}
