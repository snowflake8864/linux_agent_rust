use crate::net_app::parser_netstat::update_netstat_info;
use crate::net_app::parser_dnat::update_dnat_info;
use crate::net_app::parser_docker::update_docker_info;
use crate::net_app::model::{NETAPP_STATE,PortBusinessInfo};
#[derive(Clone)]
pub struct NetAppHandler;

impl NetAppHandler {
    pub fn new() -> Self {
        update_netstat_info();
        update_dnat_info();
        update_docker_info();
        NetAppHandler
    }
    pub async fn get_net_app_handler(
        &self,
        _data: &[u8],
        _data_len: u32,
    ) -> Result<(), String> {
        update_netstat_info();
        update_dnat_info();
        update_docker_info();
        let state = NETAPP_STATE.read().unwrap();
        state.print_contents();
        Ok(())
    }
}

