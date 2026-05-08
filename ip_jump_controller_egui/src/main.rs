use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::Duration;

use eframe::egui;
use egui_extras::{Column, TableBuilder};
use tiny_http::Server;

mod mockserver;
use mockserver::*;

// ==================== egui App ====================

struct IpJumpApp {
    state: SharedState,
    server_running: Arc<AtomicBool>,
    port_str: String,
    bind_addr: String,
    src_ip: String,
    tgt_ip: String,
    gateway: String,
    selected_mode: i32,
    active_time_str: String,
    aging_time_str: String,
    prefix_str: String,
    cycle_enabled: bool,
    cycle_pool: String,
    cycle_gw: String,
    cycle_interval: String,
    cycle_prefix: String,
    cycle_mode: i32,
    config_path: String,
    network_info: String,
    detail_open: bool,
    detail_json: String,
    status_msg: String,
    status_timer: f64,
}

impl Default for IpJumpApp {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(InnerState::default())),
            server_running: Arc::new(AtomicBool::new(false)),
            port_str: "8080".into(),
            bind_addr: "0.0.0.0".into(),
            src_ip: String::new(),
            tgt_ip: String::new(),
            gateway: String::new(),
            selected_mode: 1,
            active_time_str: "0".into(),
            aging_time_str: "2".into(),
            prefix_str: "24".into(),
            cycle_enabled: false,
            cycle_pool: String::new(),
            cycle_gw: String::new(),
            cycle_interval: "30".into(),
            cycle_prefix: "24".into(),
            cycle_mode: 1,
            config_path: "/opt/osec/net_info.ini".into(),
            network_info: String::new(),
            detail_open: false,
            detail_json: String::new(),
            status_msg: String::new(),
            status_timer: 0.0,
        }
    }
}

impl eframe::App for IpJumpApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.status_timer > 0.0 {
            self.status_timer -= ctx.input(|i| i.unstable_dt) as f64;
            if self.status_timer <= 0.0 {
                self.status_msg.clear();
            }
        }

        // Sync cycle state from UI
        {
            let mut s = self.state.lock().unwrap();
            s.cycle_strategy.enabled = self.cycle_enabled;
            s.cycle_strategy.ip_pool = self.cycle_pool
                .split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect();
            s.cycle_strategy.gateway = self.cycle_gw.clone();
            s.cycle_strategy.mode = self.cycle_mode;
            s.cycle_strategy.active_time = self.cycle_interval.parse().unwrap_or(30);
            s.cycle_strategy.prefix = self.cycle_prefix.parse().unwrap_or(24);
        }

        // Read state snapshot
        let snap = {
            let s = self.state.lock().unwrap();
            UiSnapshot {
                is_running: s.is_running,
                port: s.port,
                bind_address: s.bind_address.clone(),
                agent_host_name: s.agent_host_name.clone(),
                agent_uid: s.agent_uid.clone(),
                last_agent_ip: s.last_agent_ip.clone(),
                last_jump_status: s.last_jump_status.clone(),
                request_count: s.request_count,
                total_jumps_sent: s.total_jumps_sent,
                instruction_queue_len: s.instruction_queue.len(),
                logs: s.logs.clone(),
                cycle_pool: s.cycle_strategy.ip_pool.clone(),
                cycle_enabled: s.cycle_strategy.enabled,
            }
        };

        // Left panel
        egui::SidePanel::left("control")
            .default_width(430.0)
            .resizable(true)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    self.control_panel(ui, &snap);
                });
            });

        // Center (log)
        egui::CentralPanel::default().show(ctx, |ui| {
            self.log_panel(ui, &snap.logs);
        });

        // Detail popup
        if self.detail_open {
            egui::Window::new("Detail")
                .collapsible(false)
                .resizable(true)
                .default_size([500.0, 400.0])
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        ui.monospace(&self.detail_json);
                    });
                    if ui.button("Close").clicked() {
                        self.detail_open = false;
                    }
                });
        }

        if !self.status_msg.is_empty() {
            egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
                ui.label(&self.status_msg);
            });
        }

        ctx.request_repaint_after(Duration::from_millis(100));
    }
}

struct UiSnapshot {
    is_running: bool,
    port: u16,
    bind_address: String,
    agent_host_name: String,
    agent_uid: String,
    last_agent_ip: String,
    last_jump_status: String,
    request_count: u64,
    total_jumps_sent: u64,
    instruction_queue_len: usize,
    logs: Vec<LogEntry>,
    cycle_pool: Vec<String>,
    cycle_enabled: bool,
}

impl IpJumpApp {
    fn set_status(&mut self, msg: impl Into<String>) {
        self.status_msg = msg.into();
        self.status_timer = 3.0;
    }

    fn section_header(ui: &mut egui::Ui, title: &str) {
        ui.label(
            egui::RichText::new(title)
                .color(egui::Color32::from_rgb(159, 168, 218))
                .strong(),
        );
        ui.separator();
    }

    fn info_label(ui: &mut egui::Ui, label: &str, value: &str) {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(label).color(egui::Color32::GRAY).size(12.0));
            ui.label(egui::RichText::new(value).size(12.0));
        });
    }

    fn control_panel(&mut self, ui: &mut egui::Ui, snap: &UiSnapshot) {
        // === Mock Server ===
        ui.group(|ui| {
            Self::section_header(ui, "Mock Server");
            ui.horizontal(|ui| {
                let enable = !snap.is_running;
                ui.label("Port:");
                let mut port_edit = self.port_str.clone();
                ui.add_enabled_ui(enable, |ui| {
                    ui.add(egui::TextEdit::singleline(&mut port_edit).desired_width(60.0));
                });
                self.port_str = port_edit;

                ui.label("Bind:");
                let mut bind_edit = self.bind_addr.clone();
                ui.add_enabled_ui(enable, |ui| {
                    ui.add(egui::TextEdit::singleline(&mut bind_edit).desired_width(100.0));
                });
                self.bind_addr = bind_edit;

                if snap.is_running {
                    if ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new("Stop").color(egui::Color32::WHITE),
                            )
                            .fill(egui::Color32::from_rgb(198, 40, 40)),
                        )
                        .clicked()
                    {
                        self.stop_server();
                    }
                    ui.colored_label(egui::Color32::from_rgb(105, 240, 174), "Running");
                } else {
                    if ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new("Start").color(egui::Color32::WHITE),
                            )
                            .fill(egui::Color32::from_rgb(46, 125, 50)),
                        )
                        .clicked()
                    {
                        self.start_server();
                    }
                    ui.colored_label(egui::Color32::GRAY, "Stopped");
                }
            });
            if snap.is_running {
                ui.label(
                    egui::RichText::new(format!(
                        "Agent URL: http://{}:{}",
                        snap.bind_address, snap.port
                    ))
                    .color(egui::Color32::from_rgb(255, 183, 77))
                    .size(11.0),
                );
            }
        });

        // === Agent Status ===
        ui.group(|ui| {
            Self::section_header(ui, "Agent Status");
            let host = if snap.agent_host_name.is_empty() { "-" } else { &snap.agent_host_name };
            let uid = if snap.agent_uid.is_empty() { "-" } else { &snap.agent_uid };
            let uid_short = if uid.len() > 12 { &uid[..12] } else { uid };
            let ip = if snap.last_agent_ip.is_empty() { "-" } else { &snap.last_agent_ip };
            let jump = if snap.last_jump_status.is_empty() { "-" } else { &snap.last_jump_status };
            Self::info_label(ui, "Host:", host);
            Self::info_label(ui, "UID:", uid_short);
            Self::info_label(ui, "Logical Primary IP:", ip);
            Self::info_label(ui, "Last Jump:", jump);
            Self::info_label(ui, "Queue:", &format!("{} pending", snap.instruction_queue_len));
            Self::info_label(ui, "Requests:", &snap.request_count.to_string());
            Self::info_label(ui, "Jumps Sent:", &snap.total_jumps_sent.to_string());
        });

        // === IP Jump Instruction ===
        ui.group(|ui| {
            Self::section_header(ui, "IP Jump Instruction");
            ui.text_edit_singleline(&mut self.src_ip);
            ui.text_edit_singleline(&mut self.tgt_ip);
            ui.text_edit_singleline(&mut self.gateway);
            ui.horizontal(|ui| {
                ui.label("Mode:");
                ui.selectable_value(&mut self.selected_mode, 1, "1-Keep");
                ui.selectable_value(&mut self.selected_mode, 2, "2-Force");
            });
            ui.horizontal(|ui| {
                ui.label("Active(s):");
                ui.add(egui::TextEdit::singleline(&mut self.active_time_str).desired_width(60.0));
                ui.label("Aging(min):");
                ui.add(egui::TextEdit::singleline(&mut self.aging_time_str).desired_width(60.0));
                ui.label("Prefix:");
                ui.add(egui::TextEdit::singleline(&mut self.prefix_str).desired_width(50.0));
            });
            ui.horizontal(|ui| {
                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new("Queue Jump").color(egui::Color32::WHITE),
                        )
                        .fill(egui::Color32::from_rgb(57, 73, 171)),
                    )
                    .clicked()
                {
                    self.do_queue_jump();
                }
                if ui.button("Clear Queue").clicked() {
                    self.state.lock().unwrap().instruction_queue.clear();
                }
            });
        });

        // === Cycle Strategy ===
        ui.group(|ui| {
            Self::section_header(ui, "Cycle Strategy (Periodic)");
            ui.checkbox(&mut self.cycle_enabled, "Enable Cycle");
            ui.text_edit_singleline(&mut self.cycle_pool);
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut self.cycle_gw);
                ui.label("Interval(s):");
                ui.add(egui::TextEdit::singleline(&mut self.cycle_interval).desired_width(60.0));
                ui.label("Prefix:");
                ui.add(egui::TextEdit::singleline(&mut self.cycle_prefix).desired_width(50.0));
            });
            ui.horizontal(|ui| {
                ui.label("Mode:");
                ui.selectable_value(&mut self.cycle_mode, 1, "1-Keep");
                ui.selectable_value(&mut self.cycle_mode, 2, "2-Force");
            });

            if snap.cycle_enabled && snap.cycle_pool.len() >= 2 {
                let cycle = format!("Cycle: {} → {}", snap.cycle_pool.join(" → "), snap.cycle_pool[0]);
                ui.colored_label(egui::Color32::from_rgb(77, 208, 225), cycle);
            } else if snap.cycle_enabled {
                ui.colored_label(
                    egui::Color32::from_rgb(239, 154, 154),
                    "Need at least 2 IPs in pool",
                );
            }
        });

        // === Quick Commands ===
        ui.group(|ui| {
            Self::section_header(ui, "Quick Commands");
            ui.horizontal(|ui| {
                if ui.button("Detect Network").clicked() {
                    self.detect_network();
                }
                if ui.button("Update net_info.ini").clicked() {
                    self.update_net_info();
                }
            });
            ui.horizontal(|ui| {
                if ui.button("Restore net_info.ini").clicked() {
                    self.restore_net_info();
                }
                if ui.button("Test Connection").clicked() {
                    self.test_connection();
                }
            });
            ui.text_edit_singleline(&mut self.config_path);
        });

        // === Network Info ===
        ui.group(|ui| {
            Self::section_header(ui, "Network Info");
            ui.add(
                egui::TextEdit::multiline(&mut self.network_info)
                    .desired_rows(6)
                    .font(egui::TextStyle::Monospace)
                    .interactive(false),
            );
        });
    }

    fn log_panel(&mut self, ui: &mut egui::Ui, logs: &[LogEntry]) {
        ui.horizontal(|ui| {
            ui.heading(format!("Live Log ({})", logs.len()));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Clear").clicked() {
                    self.state.lock().unwrap().logs.clear();
                }
            });
        });

        let text_height = 18.0;
        let available_height = ui.available_height();
        let table = TableBuilder::new(ui)
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::auto().at_least(60.0))
            .column(Column::auto().at_least(30.0))
            .column(Column::auto().at_least(100.0))
            .column(Column::remainder())
            .min_scrolled_height(available_height)
            .max_scroll_height(available_height)
            .sense(egui::Sense::click());

        table.body(|body| {
            body.rows(text_height, logs.len(), |mut row| {
                let i = row.index();
                let entry = &logs[i];
                let is_in = entry.direction == "in";
                let fg = if is_in {
                    egui::Color32::from_rgb(144, 202, 249)
                } else {
                    egui::Color32::from_rgb(255, 204, 128)
                };
                row.col(|ui| {
                    ui.colored_label(fg, &entry.time);
                });
                row.col(|ui| {
                    ui.colored_label(fg, &entry.direction);
                });
                row.col(|ui| {
                    ui.colored_label(fg, &entry.path);
                });
                row.col(|ui| {
                    ui.colored_label(fg, &entry.summary);
                });
                // Click to show detail
                if row.response().clicked() {
                    if let Some(ref data) = entry.data {
                        self.detail_json =
                            serde_json::to_string_pretty(data).unwrap_or_default();
                        self.detail_open = true;
                    }
                }
            });
        });
    }

    // ==================== Actions ====================

    fn start_server(&mut self) {
        let port: u16 = self.port_str.parse().unwrap_or(8080);
        let bind = self.bind_addr.clone();
        let addr = format!("{}:{}", bind, port);

        {
            let mut s = self.state.lock().unwrap();
            s.is_running = true;
            s.port = port;
            s.bind_address = bind.clone();
        }

        self.server_running.store(true, Ordering::SeqCst);
        let state = self.state.clone();
        let running = self.server_running.clone();

        log_add(
            &state,
            LogEntry {
                time: chrono::Local::now().format("%H:%M:%S").to_string(),
                direction: "out".into(),
                path: String::new(),
                summary: format!("Server started on {}", addr),
                data: None,
            },
        );

        thread::spawn(move || {
            let server = match Server::http(&addr) {
                Ok(s) => s,
                Err(e) => {
                    log_add(
                        &state,
                        LogEntry {
                            time: chrono::Local::now().format("%H:%M:%S").to_string(),
                            direction: "out".into(),
                            path: String::new(),
                            summary: format!("Failed to start server: {}", e),
                            data: None,
                        },
                    );
                    state.lock().unwrap().is_running = false;
                    return;
                }
            };

            while running.load(Ordering::Relaxed) {
                match server.try_recv() {
                    Ok(Some(request)) => route_request(&state, request),
                    Ok(None) => thread::sleep(Duration::from_millis(5)),
                    Err(_) => break,
                }
            }

            log_add(
                &state,
                LogEntry {
                    time: chrono::Local::now().format("%H:%M:%S").to_string(),
                    direction: "out".into(),
                    path: String::new(),
                    summary: "Server stopped".into(),
                    data: None,
                },
            );
            state.lock().unwrap().is_running = false;
        });
    }

    fn stop_server(&mut self) {
        self.server_running.store(false, Ordering::SeqCst);
        self.state.lock().unwrap().is_running = false;
    }

    fn do_queue_jump(&mut self) {
        if self.tgt_ip.is_empty() {
            self.set_status("Target IP is required");
            return;
        }
        let inst = JumpInstruction {
            source_ip: self.src_ip.clone(),
            target_ip: self.tgt_ip.clone(),
            gateway: self.gateway.clone(),
            mode: self.selected_mode,
            active_time: self.active_time_str.parse().unwrap_or(0),
            aging_time: self.aging_time_str.parse().unwrap_or(2),
            prefix: self.prefix_str.parse().unwrap_or(24),
        };
        let src = if inst.source_ip.is_empty() { "auto" } else { &inst.source_ip };
        let msg = format!(
            "Jump queued: {} -> {}/{} (mode={})",
            src, inst.target_ip, inst.prefix, inst.mode
        );

        let mut s = self.state.lock().unwrap();
        s.instruction_queue.push(inst);
        if s.current_instruction.is_none() && !s.instruction_queue.is_empty() {
            s.current_instruction = Some(s.instruction_queue.remove(0));
        }
        if s.current_instruction.is_some() {
            s.ip_jump_task_pending = true;
        }
        drop(s);
        self.set_status(msg);
    }

    fn detect_network(&mut self) {
        let run = |args: &[&str]| -> String {
            Command::new("ip")
                .args(args)
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default()
        };

        let ip_out = run(&["-o", "-4", "addr", "show"]);
        let route_out = run(&["route", "show", "default"]);
        self.network_info = format!("{}\n{}", ip_out, route_out);

        if self.src_ip.is_empty() {
            for line in ip_out.lines() {
                if line.contains("inet ") && !line.contains("127.0.0.1") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    for (i, p) in parts.iter().enumerate() {
                        if *p == "inet" && i + 1 < parts.len() {
                            self.src_ip = parts[i + 1].split('/').next().unwrap_or("").to_string();
                            break;
                        }
                    }
                    if !self.src_ip.is_empty() {
                        break;
                    }
                }
            }
        }
        if self.gateway.is_empty() {
            for line in route_out.lines() {
                if let Some(pos) = line.find("via ") {
                    let rest = &line[pos + 4..];
                    if let Some(gw) = rest.split_whitespace().next() {
                        self.gateway = gw.to_string();
                        break;
                    }
                }
            }
        }
    }

    fn update_net_info(&mut self) {
        let path = self.config_path.clone();
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => {
                self.set_status(format!("Config file not found: {}", path));
                return;
            }
        };
        let _ = std::fs::write(format!("{}.bak", path), &content);

        let port = self.port_str.clone();
        let bind = self.bind_addr.clone();
        let mut new_content = content;
        new_content = replace_line(&new_content, "SERVERIPPORT=", &format!("SERVERIPPORT=http://{}:{}", bind, port));
        new_content = replace_line(&new_content, "SERVER_IP=", &format!("SERVER_IP={}", bind));
        new_content = replace_line(&new_content, "SERVER_PORT=", &format!("SERVER_PORT={}", port));

        if std::fs::write(&path, &new_content).is_ok() {
            self.set_status(format!("Updated {} -> http://{}:{}", path, bind, port));
        }
    }

    fn restore_net_info(&mut self) {
        let path = self.config_path.clone();
        let bak = format!("{}.bak", path);
        match std::fs::read_to_string(&bak) {
            Ok(c) => {
                let _ = std::fs::write(&path, c);
                self.set_status("Restored from backup");
            }
            Err(_) => self.set_status("No backup file found"),
        }
    }

    fn test_connection(&mut self) {
        let port = self.port_str.clone();
        let body = serde_json::json!({"uid":"test","macid":"test","host_name":"egui-test"});
        let body_str = serde_json::to_string(&body).unwrap_or_default();
        let addr = format!("127.0.0.1:{port}");

        match TcpStream::connect_timeout(
            &addr.parse().unwrap(),
            Duration::from_secs(3),
        ) {
            Ok(mut stream) => {
                let req = format!(
                    "POST /v1/auth HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_str}",
                    body_str.len()
                );
                let _ = stream.write_all(req.as_bytes());
                let mut resp = String::new();
                let _ = stream.read_to_string(&mut resp);
                let preview = if resp.len() > 200 { format!("{}...", &resp[..200]) } else { resp };
                self.set_status(format!("Mock server OK! Response: {preview}"));
            }
            Err(e) => {
                self.set_status(format!("Connection FAILED: {e}"));
            }
        }
    }
}

// ==================== Helpers ====================

fn replace_line(text: &str, prefix: &str, replacement: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        if line.trim_start().starts_with(prefix) {
            out.push_str(replacement);
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

// ==================== Main ====================

fn main() {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1100.0, 720.0]),
        ..Default::default()
    };

    eframe::run_native(
        "IP Jump Controller",
        options,
        Box::new(|cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(IpJumpApp::default()))
        }),
    )
    .unwrap();
}
