
use std::pin::Pin;
use common::manager::boot::BootManager;
use std::future::Future;
use tokio::time::{interval, Duration};
use logging::log_info;
use hostinfo::net_app::parser_netstat::update_netstat_info;
use hostinfo::net_app::parser_dnat::update_dnat_info;
use hostinfo::net_app::parser_docker::update_docker_info;
use hostinfo::net_app::model::write_business_ports_to_proc;

//use hostinfo::net_app::handler::NetAppHandler;

pub trait TimerTask {
    fn start_timer_task(&mut self) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>>;
}

impl TimerTask for BootManager {
    fn start_timer_task(&mut self) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>> {
        Box::pin(async move {
            let mut interval = interval(Duration::from_secs(30));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        //log_info!("定时任务");
                        update_netstat_info();
                        update_dnat_info();
                        update_docker_info();
                        write_business_ports_to_proc();

                    }
                }
            }
        })
    }
}
