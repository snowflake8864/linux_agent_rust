use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tiny_http::{Request, Response};

// ==================== Data ====================

#[derive(Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct LogEntry {
    pub time: String,
    pub direction: String,
    pub path: String,
    pub summary: String,
    pub data: Option<serde_json::Value>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct JumpInstruction {
    pub source_ip: String,
    pub target_ip: String,
    pub gateway: String,
    pub mode: i32,
    pub active_time: i32,
    pub aging_time: i32,
    pub prefix: i32,
}

impl JumpInstruction {
    pub fn target_ip_cidr(&self) -> String {
        if self.target_ip.contains('/') {
            self.target_ip.clone()
        } else {
            format!("{}/{}", self.target_ip, self.prefix)
        }
    }

    pub fn source_ip_bare(&self) -> String {
        if self.source_ip.is_empty() {
            return String::new();
        }
        self.source_ip.split('/').next().unwrap_or("").to_string()
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "source_ip": self.source_ip_bare(),
            "target_ip": self.target_ip_cidr(),
            "gateway": self.gateway,
            "mode": self.mode,
            "active_time": self.active_time,
            "aging_time": self.aging_time,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.target_ip.is_empty()
    }
}

#[derive(Clone, Default)]
pub struct CycleStrategy {
    pub enabled: bool,
    pub ip_pool: Vec<String>,
    pub gateway: String,
    pub mode: i32,
    pub active_time: i32,
    pub aging_time: i32,
    pub prefix: i32,
    pub current_index: usize,
}

impl CycleStrategy {
    pub fn next_instruction(&mut self, current_agent_ip: &str) -> JumpInstruction {
        if self.ip_pool.len() < 2 {
            return JumpInstruction::default();
        }
        let start_idx = self
            .ip_pool
            .iter()
            .position(|ip| ip == current_agent_ip)
            .unwrap_or(self.current_index);
        let next_idx = (start_idx + 1) % self.ip_pool.len();
        self.current_index = next_idx;
        JumpInstruction {
            target_ip: self.ip_pool[next_idx].clone(),
            gateway: self.gateway.clone(),
            mode: self.mode,
            active_time: self.active_time,
            aging_time: self.aging_time,
            prefix: self.prefix,
            ..Default::default()
        }
    }
}

// ==================== State ====================

pub struct InnerState {
    pub is_running: bool,
    pub port: u16,
    pub bind_address: String,
    pub agent_host_name: String,
    pub agent_uid: String,
    pub agent_macid: String,
    pub last_agent_ip: String,
    pub last_jump_status: String,
    pub request_count: u64,
    pub total_jumps_sent: u64,
    pub instruction_queue: Vec<JumpInstruction>,
    pub current_instruction: Option<JumpInstruction>,
    pub ip_jump_task_pending: bool,
    pub cycle_strategy: CycleStrategy,
    pub logs: Vec<LogEntry>,
}

impl Default for InnerState {
    fn default() -> Self {
        Self {
            is_running: false, port: 8080, bind_address: "0.0.0.0".into(),
            agent_host_name: String::new(), agent_uid: String::new(), agent_macid: String::new(),
            last_agent_ip: String::new(), last_jump_status: String::new(),
            request_count: 0, total_jumps_sent: 0,
            instruction_queue: vec![], current_instruction: None, ip_jump_task_pending: false,
            cycle_strategy: CycleStrategy::default(), logs: vec![],
        }
    }
}

pub type SharedState = Arc<Mutex<InnerState>>;

// ==================== Helpers ====================

pub fn log_add(state: &SharedState, entry: LogEntry) {
    let mut s = state.lock().unwrap();
    s.logs.insert(0, entry);
    if s.logs.len() > 500 { s.logs.truncate(500); }
}

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()
}

fn summarize_req(path: &str, req: &serde_json::Value) -> String {
    let s = |k: &str| req.get(k).and_then(|v| v.as_str()).unwrap_or("");
    match path {
        "/v1/auth" => format!("AUTH uid={}, host={}, ip={}", s("uid"), s("host_name"), s("ip")),
        "/v1/gettask" => "GET-TASK".into(),
        "/v1/getIpJump" => "GET-IP-JUMP".into(),
        "/v1/putIpJump" => format!("PUT-IP-JUMP status={}, src={}, tgt={}, agent_ip={}",
            req.get("status").and_then(|v| v.as_i64()).unwrap_or(0), s("source_ip"), s("target_ip"), s("agent_ip")),
        "/v1/uploadIp" => format!("UPLOAD-IP: {}", s("ip")),
        _ => format!("{path}"),
    }
}

fn summarize_resp(resp: &serde_json::Value) -> String {
    let code = resp["code"].as_str().unwrap_or("");
    let data = &resp["data"];
    if data.get("tasklist").is_some() { return format!("code={code}, tasklist={}", data["tasklist"]); }
    if data.get("target_ip").is_some() {
        return format!("code={code}, target={}, mode={}, active={}s",
            data["target_ip"].as_str().unwrap_or(""), data["mode"].as_i64().unwrap_or(0),
            data["active_time"].as_i64().unwrap_or(0));
    }
    if let Some(t) = data.get("token").and_then(|v| v.as_str()) {
        return format!("code={code}, token={}", if t.len() > 20 { &t[..20] } else { t });
    }
    format!("code={code}")
}

// ==================== Request Router ====================

pub fn route_request(state: &SharedState, mut request: Request) {
    let path = request.url().to_string();
    let method = request.method().clone();
    let method_str = method.as_str().to_string();

    let mut body = String::new();
    let _ = request.as_reader().read_to_string(&mut body);
    let req_data: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);

    let auth = request.headers().iter()
        .find(|h| h.field.as_str().as_str().to_lowercase() == "authorization")
        .map(|h| h.value.as_str().to_string()).unwrap_or_default();

    // Collect pending log entries
    let mut pending_logs: Vec<LogEntry> = Vec::new();
    let now = || chrono::Local::now().format("%H:%M:%S").to_string();
    let resp: serde_json::Value;
    {
        let mut s = state.lock().unwrap();
        s.request_count += 1;

        match path.as_str() {
            "/v1/auth" => {
                s.agent_uid = req_data["uid"].as_str().unwrap_or("").to_string();
                s.agent_macid = req_data["macid"].as_str().unwrap_or("").to_string();
                s.agent_host_name = req_data["host_name"].as_str().unwrap_or("").to_string();
                let ips = req_data["ip"].as_str().unwrap_or("");
                if !ips.is_empty() { s.last_agent_ip = ips.split(',').next().unwrap_or("").to_string(); }
                resp = serde_json::json!({"code":"000000","msg":"success",
                    "data":{"token":format!("mock-token-{}",now_ms())}});
            }
            "/v1/gettask" => {
                let mut tl: Vec<i32> = vec![];
                if s.ip_jump_task_pending { tl.push(37); }
                resp = serde_json::json!({"code":"000000","msg":"success","data":{"tasklist":tl}});
            }
            "/v1/getIpJump" => {
                // Extract full state needed for this handler
                let inst = s.current_instruction.take();
                let has_queue = !s.instruction_queue.is_empty();
                let cyc_enabled = s.cycle_strategy.enabled;
                let last_agent_ip = s.last_agent_ip.clone();

                if let Some(inst) = inst {
                    s.total_jumps_sent += 1;
                    let nxt = inst.target_ip_cidr().split('/').next().unwrap_or("").to_string();
                    if has_queue {
                        s.current_instruction = Some(s.instruction_queue.remove(0));
                        s.ip_jump_task_pending = true;
                    } else if cyc_enabled {
                        let next = s.cycle_strategy.next_instruction(&nxt);
                        if !next.is_empty() {
                            s.current_instruction = Some(next);
                            s.ip_jump_task_pending = true;
                        } else { s.ip_jump_task_pending = false; }
                    } else { s.ip_jump_task_pending = false; }
                    resp = serde_json::json!({"code":"000000","msg":"success","data":inst.to_json()});
                    pending_logs.push(LogEntry {
                        time: now(), direction: "out".into(), path: "/v1/getIpJump".into(),
                        summary: format!("QUEUE: {} remaining", s.instruction_queue.len()),
                        data: None,
                    });
                } else if cyc_enabled {
                    let mut inst = s.cycle_strategy.next_instruction(&last_agent_ip);
                    if !inst.is_empty() {
                        s.total_jumps_sent += 1;
                        let next = s.cycle_strategy.next_instruction(&inst.target_ip);
                        if !next.is_empty() {
                            s.current_instruction = Some(next);
                            s.ip_jump_task_pending = true;
                        }
                    }
                    // fudge inst back (moved out)
                    inst = if !inst.is_empty() {
                        JumpInstruction { target_ip: last_agent_ip.clone(), ..Default::default() }
                    } else { JumpInstruction::default() };
                    let (inst_data, empty, reason) = if !inst.is_empty() {
                        (inst.to_json(), false, String::new())
                    } else {
                        let reason = format!("cycle enabled but ipPool has only {} IPs (need >=2), lastAgentIp={last_agent_ip}",
                            s.cycle_strategy.ip_pool.len());
                        (serde_json::json!({"source_ip":"","target_ip":"","gateway":"","active_time":0,"aging_time":2,"mode":1}), true, reason)
                    };
                    resp = serde_json::json!({"code":"000000","msg":"success","data":inst_data});
                    if empty {
                        pending_logs.push(LogEntry { time: now(), direction: "out".into(),
                            path: "/v1/getIpJump".into(), summary: format!("EMPTY: {reason}"), data: None });
                    }
                } else {
                    let reason = "no instruction queued and cycle not enabled";
                    resp = serde_json::json!({"code":"000000","msg":"success",
                        "data":{"source_ip":"","target_ip":"","gateway":"","active_time":0,"aging_time":2,"mode":1}});
                    pending_logs.push(LogEntry { time: now(), direction: "out".into(),
                        path: "/v1/getIpJump".into(), summary: format!("EMPTY: {reason}"), data: None });
                }
            }
            "/v1/putIpJump" => {
                let status = req_data["status"].as_i64().unwrap_or(0);
                let agent_ip = req_data["agent_ip"].as_str().unwrap_or("");
                s.last_jump_status = if status == 1 { "SUCCESS".into() } else { "FAILED".into() };
                if !agent_ip.is_empty() { s.last_agent_ip = agent_ip.split(',').next().unwrap_or("").to_string(); }
                resp = serde_json::json!({"code":"000000","msg":"success"});
                pending_logs.push(LogEntry {
                    time: now(), direction: "in".into(), path: "/v1/putIpJump".into(),
                    summary: format!("Jump result: status={status}, src={}, tgt={}, agent={}, reason={}",
                        req_data["source_ip"].as_str().unwrap_or(""),
                        req_data["target_ip"].as_str().unwrap_or(""),
                        req_data["agent_ip"].as_str().unwrap_or(""),
                        req_data["reason"].as_str().unwrap_or("")),
                    data: Some(req_data.clone()),
                });
            }
            "/v1/uploadIp" => {
                let ips = req_data["ip"].as_str().unwrap_or("");
                if !ips.is_empty() {
                    s.last_agent_ip = ips.split(',').next().unwrap_or("").to_string();
                    let la = s.last_agent_ip.clone();
                    pending_logs.push(LogEntry {
                        time: now(), direction: "in".into(), path: "/v1/uploadIp".into(),
                        summary: format!("IP report: logical_primary={la}, all={ips}"),
                        data: Some(req_data.clone()),
                    });
                }
                resp = serde_json::json!({"code":"000000","msg":"success"});
            }
            "/v1/getToken" => {
                resp = serde_json::json!({"code":"000000","msg":"success",
                    "data":{"token":format!("mock-token-{}",now_ms())}});
            }
            "/v1/reportTaskCompletion" | "/v1/uploadproc" | "/v1/upload/suffix/exe"
            | "/v1/getconf" | "/v1/getprotect" | "/v1/closetask" => {
                resp = serde_json::json!({"code":"000000","msg":"success"});
            }
            _ => {
                resp = serde_json::json!({"code":"000000","msg":"success","data":{}});
            }
        }
    }

    // Add main request log
    let auth_tag = if auth.is_empty() { "" } else { " [token]" };
    let main_log = LogEntry {
        time: now(), direction: "in".into(), path: path.clone(),
        summary: format!("{} {path}{auth_tag}\n  >> {}\n  << {}",
            method_str, summarize_req(&path, &req_data), summarize_resp(&resp)),
        data: Some(serde_json::json!({"request": req_data, "response": resp.clone()})),
    };
    {
        let mut s = state.lock().unwrap();
        s.logs.insert(0, main_log);
        for l in pending_logs { s.logs.insert(0, l); }
        if s.logs.len() > 500 { s.logs.truncate(500); }
    }

    let resp_body = serde_json::to_string(&resp).unwrap_or_default();
    let response = Response::from_string(resp_body).with_status_code(200);
    let _ = request.respond(response);
}
