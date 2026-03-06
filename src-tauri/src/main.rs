#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::net::{UdpSocket, TcpListener};
use std::thread;
use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex};
use std::io::Read;
use std::collections::{HashMap, HashSet};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use socket2::{Socket, Domain, Type, Protocol};
use sodiumoxide::crypto::secretbox;
use chrono::Local;
use std::fs::File;
use std::io::BufReader;
use sha2::{Sha256, Digest};

const DISCOVERY_PORT: u16 = 5000;
const DATA_PORT: u16 = 5001;
const MAX_TTL: u8 = 5;
const CHUNK_SIZE: usize = 4096;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PeerInfo {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub port: u16,
    pub last_seen: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Message {
    pub id: String,
    pub sender_id: String,
    pub sender_name: String,
    pub content: String,
    pub timestamp: String,
    pub is_file: bool,
    pub file_name: Option<String>,
    pub file_size: Option<u64>,
    pub progress: f32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PacketType {
    Hello,
    Chat(String),
    FileChunk { filename: String, total_size: u64, chunk_index: u64, data: Vec<u8>, hash: String },
    FileAck { filename: String, chunk_index: u64 },
    Audio(Vec<u8>),
    Ack(String),
    Ping,
    Pong,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MeshPacket {
    pub msg_id: String,
    pub src_id: String,
    pub dst_id: Option<String>,
    pub ttl: u8,
    pub hop_count: u8,
    pub payload: PacketType,
    pub timestamp: u64,
}

pub struct SecureChannel {
    key: secretbox::Key,
}

impl SecureChannel {
    pub fn new() -> Self {
        if sodiumoxide::init().is_err() { eprintln!("Crypto init failed"); }
        let key_bytes = [42, 13, 7, 99, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28];
        Self { key: secretbox::Key(key_bytes) }
    }
    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let nonce = secretbox::gen_nonce();
        let encrypted = secretbox::seal(data, &nonce, &self.key);
        let mut result = nonce.0.to_vec();
        result.extend(encrypted);
        result
    }
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if ciphertext.len() < secretbox::NONCEBYTES { return Err("Invalid"); }
        let mut nonce_bytes = [0u8; secretbox::NONCEBYTES];
        nonce_bytes.copy_from_slice(&ciphertext[..secretbox::NONCEBYTES]);
        let nonce = secretbox::Nonce(nonce_bytes);
        secretbox::open(&ciphertext[secretbox::NONCEBYTES..], &nonce, &self.key).map_err(|_| "Fail")
    }
}

pub struct AppState {
    pub peers: Arc<Mutex<HashMap<String, PeerInfo>>>,
    pub messages: Arc<Mutex<Vec<Message>>>,
    pub logs: Arc<Mutex<Vec<String>>>,
    pub my_id: String,
    pub my_name: String,
    pub crypto: Arc<Mutex<SecureChannel>>,
    pub received_msgs: Arc<Mutex<HashSet<String>>>,
    pub file_transfers: Arc<Mutex<HashMap<String, FileTransferState>>>,
    pub metrics: Arc<Mutex<Metrics>>,
}

pub struct FileTransferState {
    pub filename: String,
    pub total_size: u64,
    pub received_chunks: HashMap<u64, Vec<u8>>,
    pub next_expected: u64,
}

pub struct Metrics {
    pub ping_ms: f32,
    pub packet_loss_percent: f32,
    pub sent_packets: u32,
    pub lost_packets: u32,
    pub last_update: Instant,
}

impl AppState {
    pub fn new() -> Self {
        let my_id = Uuid::new_v4().to_string()[..8].to_string();
        let state = Self {
            peers: Arc::new(Mutex::new(HashMap::new())),
            messages: Arc::new(Mutex::new(Vec::new())),
            logs: Arc::new(Mutex::new(vec![format!("System initialized. ID: {}", my_id)])),
            my_name: format!("User_{}", my_id),
            my_id: my_id.clone(),
            crypto: Arc::new(Mutex::new(SecureChannel::new())),
            received_msgs: Arc::new(Mutex::new(HashSet::new())),
            file_transfers: Arc::new(Mutex::new(HashMap::new())),
            metrics: Arc::new(Mutex::new(Metrics {
                ping_ms: 0.0,
                packet_loss_percent: 0.0,
                sent_packets: 0,
                lost_packets: 0,
                last_update: Instant::now(),
            })),
        };
        
        let p_clone = Arc::clone(&state.peers);
        let m_clone = Arc::clone(&state.messages);
        let c_clone = Arc::clone(&state.crypto);
        let l_clone = Arc::clone(&state.logs);
        let r_clone = Arc::clone(&state.received_msgs);
        let f_clone = Arc::clone(&state.file_transfers);
        let met_clone = Arc::clone(&state.metrics);
        let id_clone = my_id.clone();
        let name_clone = state.my_name.clone();

        thread::spawn(move || Self::network_loop(id_clone, name_clone, p_clone, m_clone, l_clone, c_clone, r_clone, f_clone, met_clone));
        state
    }

    fn add_log(logs: &Arc<Mutex<Vec<String>>>, msg: &str) {
        let mut l = logs.lock().unwrap();
        let time = Local::now().format("%H:%M:%S%.3f").to_string();
        l.push(format!("[{}] {}", time, msg));
        if l.len() > 200 { l.remove(0); }
    }

    fn get_local_ip() -> String {
        let s = UdpSocket::bind("0.0.0.0:0").unwrap();
        s.connect("8.8.8.8:80").unwrap();
        s.local_addr().unwrap().ip().to_string()
    }

    fn create_udp_socket(port: u16) -> UdpSocket {
        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        sock.set_reuse_address(true).unwrap();
        sock.set_broadcast(true).unwrap();
        if let Err(e) = sock.bind(&addr.into()) { eprintln!("Bind error: {}", e); }
        UdpSocket::from(sock)
    }

    fn serialize_packet(packet: &MeshPacket, crypto: &Mutex<SecureChannel>) -> Vec<u8> {
        let json = serde_json::to_vec(packet).unwrap();
        crypto.lock().unwrap().encrypt(&json)
    }

    fn deserialize_packet(data: &[u8], crypto: &Mutex<SecureChannel>) -> Option<MeshPacket> {
        let decrypted = crypto.lock().unwrap().decrypt(data).ok()?;
        serde_json::from_slice(&decrypted).ok()
    }

    fn network_loop(
        my_id: String, my_name: String, 
        peers: Arc<Mutex<HashMap<String, PeerInfo>>>, 
        messages: Arc<Mutex<Vec<Message>>>, 
        logs: Arc<Mutex<Vec<String>>>, 
        crypto: Arc<Mutex<SecureChannel>>,
        received_msgs: Arc<Mutex<HashSet<String>>>,
        file_transfers: Arc<Mutex<HashMap<String, FileTransferState>>>,
        metrics: Arc<Mutex<Metrics>>
    ) {
        let socket = Self::create_udp_socket(DISCOVERY_PORT);
        let my_ip = Self::get_local_ip();
        Self::add_log(&logs, &format!("Discovery on {}:{}", my_ip, DISCOVERY_PORT));

        let c_clone = Arc::clone(&crypto);
        let l_clone = Arc::clone(&logs);
        let m_clone = Arc::clone(&messages);
        let p_clone = Arc::clone(&peers);
        let r_clone = Arc::clone(&received_msgs);
        let f_clone = Arc::clone(&file_transfers);
        let met_clone = Arc::clone(&metrics);

        thread::spawn(move || Self::tcp_listener(DATA_PORT, m_clone, l_clone, c_clone, r_clone, f_clone, met_clone, p_clone));

        loop {
            let hello = MeshPacket {
                msg_id: Uuid::new_v4().to_string(),
                src_id: my_id.clone(),
                dst_id: None,
                ttl: MAX_TTL,
                hop_count: 0,
                payload: PacketType::Hello,
                timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            };
            let data = Self::serialize_packet(&hello, &crypto);
            let _ = socket.send_to(&data, "255.255.255.255:5000");
            thread::sleep(Duration::from_secs(2));

            socket.set_read_timeout(Some(Duration::from_millis(100))).ok();
            let mut buf = [0; 65535];
            if let Ok((len, addr)) = socket.recv_from(&mut buf) {
                if let Some(packet) = Self::deserialize_packet(&buf[..len], &crypto) {
                    Self::process_packet(packet, &addr.ip().to_string(), &my_id, &my_name, &peers, &messages, &logs, &received_msgs, &file_transfers, &crypto, &metrics, &socket);
                }
            }
        }
    }

    fn process_packet(
        packet: MeshPacket,
        sender_ip: &str,
        my_id: &str,
        _my_name: &str,
        peers: &Arc<Mutex<HashMap<String, PeerInfo>>>,
        messages: &Arc<Mutex<Vec<Message>>>,
        logs: &Arc<Mutex<Vec<String>>>,
        received_msgs: &Arc<Mutex<HashSet<String>>>,
        file_transfers: &Arc<Mutex<HashMap<String, FileTransferState>>>,
        crypto: &Arc<Mutex<SecureChannel>>,
        metrics: &Arc<Mutex<Metrics>>,
        socket: &UdpSocket
    ) {
        if packet.src_id == my_id { return; }
        
        // Дедупликация
        let mut r_lock = received_msgs.lock().unwrap();
        if r_lock.contains(&packet.msg_id) {
            return; 
        }
        r_lock.insert(packet.msg_id.clone());
        if r_lock.len() > 1000 { r_lock.clear(); } 
        drop(r_lock);

        // Mesh Ретрансляция
        if packet.ttl > 1 && packet.dst_id.as_ref().map_or(true, |id| id != my_id) {
            let mut forward_packet = packet.clone();
            forward_packet.ttl -= 1;
            forward_packet.hop_count += 1;
            let data = Self::serialize_packet(&forward_packet, crypto);
            let _ = socket.send_to(&data, "255.255.255.255:5000");
        }

        // Обработка если пакет для меня
        if packet.dst_id.as_ref().map_or(true, |id| id == my_id) {
            match packet.payload {
                PacketType::Hello => {
                    let mut p_lock = peers.lock().unwrap();
                    p_lock.entry(packet.src_id.clone()).or_insert_with(|| PeerInfo {
                        id: packet.src_id.clone(),
                        name: format!("User_{}", &packet.src_id[..4]),
                        ip: sender_ip.to_string(),
                        port: DATA_PORT,
                        last_seen: packet.timestamp,
                    });
                    Self::add_log(logs, &format!("Found peer: {} via {} hops", packet.src_id, packet.hop_count));
                },
                PacketType::Chat(text) => {
                    let msg = Message {
                        id: packet.msg_id.clone(),
                        sender_id: packet.src_id.clone(),
                        sender_name: format!("User@{}", sender_ip),
                        content: text,
                        timestamp: Local::now().format("%H:%M:%S").to_string(),
                        is_file: false,
                        file_name: None,
                        file_size: None,
                        progress: 0.0,
                    };
                    messages.lock().unwrap().push(msg);
                    
                    let ack = MeshPacket {
                        msg_id: Uuid::new_v4().to_string(),
                        src_id: my_id.to_string(),
                        dst_id: Some(packet.src_id),
                        ttl: MAX_TTL,
                        hop_count: 0,
                        payload: PacketType::Ack(packet.msg_id),
                        timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                    };
                    let _ = socket.send_to(&Self::serialize_packet(&ack, crypto), format!("{}:{}", sender_ip, DISCOVERY_PORT).as_str());
                },
                PacketType::FileChunk { filename, total_size, chunk_index, data, hash: _ } => {
                    let mut ft_lock = file_transfers.lock().unwrap();
                    let entry = ft_lock.entry(filename.clone()).or_insert_with(|| FileTransferState {
                        filename: filename.clone(),
                        total_size,
                        received_chunks: HashMap::new(),
                        next_expected: 0,
                    });
                    
                    entry.received_chunks.insert(chunk_index, data);
                    if chunk_index == entry.next_expected {
                        entry.next_expected += 1;
                    }
                    
                    let total_chunks = (total_size as f32 / CHUNK_SIZE as f32).ceil();
                    let progress = (entry.received_chunks.len() as f32 / total_chunks) * 100.0;
                    
                    let msg_content = format!("Receiving {}... {:.1}%", filename, progress);
                    
                    let mut msgs = messages.lock().unwrap();
                    let update_existing = msgs.iter_mut().rev().find(|m| m.file_name.as_ref() == Some(&filename) && m.is_file);
                    
                    if let Some(last) = update_existing {
                        last.progress = progress;
                        last.content = msg_content;
                    } else {
                        msgs.push(Message {
                            id: packet.msg_id.clone(),
                            sender_id: packet.src_id.clone(),
                            sender_name: format!("File@{}", sender_ip),
                            content: msg_content,
                            timestamp: Local::now().format("%H:%M:%S").to_string(),
                            is_file: true,
                            file_name: Some(filename.clone()),
                            file_size: Some(total_size),
                            progress,
                        });
                    }

                    let ack = MeshPacket {
                        msg_id: Uuid::new_v4().to_string(),
                        src_id: my_id.to_string(),
                        dst_id: Some(packet.src_id),
                        ttl: MAX_TTL,
                        hop_count: 0,
                        payload: PacketType::FileAck { filename: filename.clone(), chunk_index },
                        timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                    };
                    let _ = socket.send_to(&Self::serialize_packet(&ack, crypto), format!("{}:{}", sender_ip, DISCOVERY_PORT).as_str());
                },
                PacketType::Audio(_) => { }, 
                PacketType::Ping => {
                     let pong = MeshPacket {
                        msg_id: Uuid::new_v4().to_string(),
                        src_id: my_id.to_string(),
                        dst_id: Some(packet.src_id),
                        ttl: MAX_TTL,
                        hop_count: 0,
                        payload: PacketType::Pong,
                        timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                    };
                    let _ = socket.send_to(&Self::serialize_packet(&pong, crypto), format!("{}:{}", sender_ip, DISCOVERY_PORT).as_str());
                },
                PacketType::Pong => {
                    let mut met = metrics.lock().unwrap();
                    met.ping_ms = (Instant::now().duration_since(met.last_update).as_secs_f32()) * 1000.0;
                    met.last_update = Instant::now();
                },
                _ => {}
            }
        }
    }

    fn tcp_listener(
        port: u16, 
        messages: Arc<Mutex<Vec<Message>>>, 
        logs: Arc<Mutex<Vec<String>>>, 
        crypto: Arc<Mutex<SecureChannel>>,
        received_msgs: Arc<Mutex<HashSet<String>>>,
        file_transfers: Arc<Mutex<HashMap<String, FileTransferState>>>,
        metrics: Arc<Mutex<Metrics>>,
        peers: Arc<Mutex<HashMap<String, PeerInfo>>>
    ) {
        let listener = match TcpListener::bind(format!("0.0.0.0:{}", port)) {
            Ok(l) => { Self::add_log(&logs, &format!("TCP Listening on {}", port)); l },
            Err(e) => { Self::add_log(&logs, &format!("TCP Bind error: {}", e)); return; }
        };

        for stream in listener.incoming() {
            if let Ok(mut stream) = stream {
                let peer_addr = stream.peer_addr().map(|a| a.ip().to_string()).unwrap_or("unknown".to_string());
                let mut buffer = [0; 65535];
                if let Ok(len) = stream.read(&mut buffer) {
                    if len > 0 {
                         if let Ok(decrypted) = crypto.lock().unwrap().decrypt(&buffer[..len]) {
                             if let Ok(packet) = serde_json::from_slice::<MeshPacket>(&decrypted) {
                                 let socket = Self::create_udp_socket(0); 
                                 Self::process_packet(packet, &peer_addr, "me", "me", &peers, &messages, &logs, &received_msgs, &file_transfers, &crypto, &metrics, &socket);
                             }
                         }
                    }
                }
            }
        }
    }

    pub fn send_message(&self, content: String) -> Result<(), String> {
        let msg_id = Uuid::new_v4().to_string();
        let packet = MeshPacket {
            msg_id: msg_id.clone(),
            src_id: self.my_id.clone(),
            dst_id: None,
            ttl: MAX_TTL,
            hop_count: 0,
            payload: PacketType::Chat(content.clone()),
            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        };
        
        let msg = Message {
            id: msg_id.clone(),
            sender_id: self.my_id.clone(),
            sender_name: self.my_name.clone(),
            content,
            timestamp: Local::now().format("%H:%M:%S").to_string(),
            is_file: false,
            file_name: None,
            file_size: None,
            progress: 0.0,
        };
        self.messages.lock().unwrap().push(msg);

        let data = Self::serialize_packet(&packet, &self.crypto);
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
        socket.set_broadcast(true).map_err(|e| e.to_string())?;
        
        let mut sent = false;
        for peer in self.peers.lock().unwrap().values() {
            if socket.send_to(&data, format!("{}:{}", peer.ip, DISCOVERY_PORT).as_str()).is_ok() {
                sent = true;
                let mut met = self.metrics.lock().unwrap();
                met.sent_packets += 1;
                met.last_update = Instant::now();
            }
        }
        if !sent { return Err("No peers".to_string()); }
        Ok(())
    }

    pub fn send_file(&self, path: String) -> Result<(), String> {
        let file = File::open(&path).map_err(|e| e.to_string())?;
        let total_size = file.metadata().map_err(|e| e.to_string())?.len();
        let filename = path.split('\\').last().or(path.split('/').last()).unwrap_or("file").to_string();
        
        let mut reader = BufReader::new(file);
        let mut buffer = vec![0; CHUNK_SIZE];
        let mut chunk_index = 0;

        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
        socket.set_broadcast(true).map_err(|e| e.to_string())?;

        loop {
            let n = reader.read(&mut buffer).map_err(|e| e.to_string())?;
            if n == 0 { break; }
            
            let chunk_data = buffer[..n].to_vec();
            let mut hasher = Sha256::new();
            hasher.update(&chunk_data);
            let hash = format!("{:x}", hasher.finalize());

            let packet = MeshPacket {
                msg_id: Uuid::new_v4().to_string(),
                src_id: self.my_id.clone(),
                dst_id: None,
                ttl: MAX_TTL,
                hop_count: 0,
                payload: PacketType::FileChunk {
                    filename: filename.clone(),
                    total_size,
                    chunk_index,
                    data: chunk_data,
                    hash,
                },
                timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            };

            let data = Self::serialize_packet(&packet, &self.crypto);
            for peer in self.peers.lock().unwrap().values() {
                let _ = socket.send_to(&data, format!("{}:{}", peer.ip, DISCOVERY_PORT).as_str());
            }
            
            let progress = ((chunk_index as f32 * CHUNK_SIZE as f32) / total_size as f32) * 100.0;
            let msg = Message {
                id: packet.msg_id,
                sender_id: self.my_id.clone(),
                sender_name: self.my_name.clone(),
                content: format!("Sending {}... {:.1}%", filename, progress),
                timestamp: Local::now().format("%H:%M:%S").to_string(),
                is_file: true,
                file_name: Some(filename.clone()),
                file_size: Some(total_size),
                progress,
            };
            self.messages.lock().unwrap().push(msg);
            
            chunk_index += 1;
            thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    }

    pub fn send_ping(&self) {
        let packet = MeshPacket {
            msg_id: Uuid::new_v4().to_string(),
            src_id: self.my_id.clone(),
            dst_id: None,
            ttl: MAX_TTL,
            hop_count: 0,
            payload: PacketType::Ping,
            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        };
        let data = Self::serialize_packet(&packet, &self.crypto);
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        socket.set_broadcast(true).unwrap();
        for peer in self.peers.lock().unwrap().values() {
            let _ = socket.send_to(&data, format!("{}:{}", peer.ip, DISCOVERY_PORT).as_str());
        }
        let mut met = self.metrics.lock().unwrap();
        met.last_update = Instant::now();
        met.sent_packets += 1;
    }

    pub fn get_peers(&self) -> Vec<PeerInfo> { self.peers.lock().unwrap().values().cloned().collect() }
    pub fn get_messages(&self) -> Vec<Message> { self.messages.lock().unwrap().clone() }
    pub fn get_logs(&self) -> Vec<String> { self.logs.lock().unwrap().clone() }
    pub fn get_metrics(&self) -> (f32, f32) {
        let m = self.metrics.lock().unwrap();
        (m.ping_ms, m.packet_loss_percent)
    }
}

#[tauri::command]
fn get_peers(state: tauri::State<AppState>) -> Vec<PeerInfo> { state.get_peers() }
#[tauri::command]
fn get_messages(state: tauri::State<AppState>) -> Vec<Message> { state.get_messages() }
#[tauri::command]
fn get_logs(state: tauri::State<AppState>) -> Vec<String> { state.get_logs() }
#[tauri::command]
fn send_message(state: tauri::State<AppState>, content: String) -> Result<(), String> { state.send_message(content) }
#[tauri::command]
fn send_file(state: tauri::State<AppState>, path: String) -> Result<(), String> { state.send_file(path) }
#[tauri::command]
fn send_ping(state: tauri::State<AppState>) { state.send_ping() }
#[tauri::command]
fn get_metrics(state: tauri::State<AppState>) -> (f32, f32) { state.get_metrics() }
#[tauri::command]
fn get_my_id(state: tauri::State<AppState>) -> String { state.my_id.clone() }

fn main() {
    let state = AppState::new();
    println!("DCS Mesh Victory Started. ID: {}", state.my_id);
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init()) // <-- ДОБАВЛЕНО: Инициализация плагина диалогов
        .manage(state)
        .invoke_handler(tauri::generate_handler![get_peers, get_messages, send_message, get_my_id, get_logs, send_file, send_ping, get_metrics])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}