#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::net::{UdpSocket, TcpStream, TcpListener};
use std::thread;
use std::time::Duration;
use std::sync::{Arc, Mutex};
use std::io::{Read, Write};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use socket2::{Socket, Domain, Type, Protocol};
use sodiumoxide::crypto::secretbox;
use chrono::Local;

const DISCOVERY_PORT: u16 = 5000;
const CHAT_PORT: u16 = 5001;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PeerInfo {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Message {
    pub id: String,
    pub sender_id: String,
    pub sender_name: String,
    pub content: String,
    pub timestamp: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Packet {
    Hello(PeerInfo),
    Chat(Vec<u8>),
}

pub struct SecureChannel {
    key: secretbox::Key,
}

impl SecureChannel {
    pub fn new() -> Self {
        if sodiumoxide::init().is_err() { eprintln!("Crypto init failed"); }
        let key_bytes = [
            42, 13, 7, 99, 1, 2, 3, 4, 
            5, 6, 7, 8, 9, 10, 11, 12, 
            13, 14, 15, 16, 17, 18, 19, 20, 
            21, 22, 23, 24, 25, 26, 27, 28
        ];
        let key = secretbox::Key(key_bytes);
        Self { key }
    }

    pub fn encrypt(&self, plaintext: &str) -> Vec<u8> {
        let nonce = secretbox::gen_nonce();
        let encrypted = secretbox::seal(plaintext.as_bytes(), &nonce, &self.key);
        let mut result = nonce.0.to_vec();
        result.extend(encrypted);
        result
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<String, &'static str> {
        if ciphertext.len() < secretbox::NONCEBYTES { return Err("Invalid length"); }
        let mut nonce_bytes = [0u8; secretbox::NONCEBYTES];
        nonce_bytes.copy_from_slice(&ciphertext[..secretbox::NONCEBYTES]);
        let nonce = secretbox::Nonce(nonce_bytes);
        let decrypted = secretbox::open(&ciphertext[secretbox::NONCEBYTES..], &nonce, &self.key).map_err(|_| "Decrypt fail")?;
        String::from_utf8(decrypted).map_err(|_| "UTF8 Error")
    }
}

pub struct AppState {
    pub peers: Arc<Mutex<Vec<PeerInfo>>>,
    pub messages: Arc<Mutex<Vec<Message>>>,
    pub logs: Arc<Mutex<Vec<String>>>,
    pub my_id: String,
    pub my_name: String,
    pub crypto: Arc<Mutex<SecureChannel>>,
}

impl AppState {
    pub fn new() -> Self {
        let my_id = Uuid::new_v4().to_string()[..8].to_string();
        let state = Self {
            peers: Arc::new(Mutex::new(Vec::new())),
            messages: Arc::new(Mutex::new(Vec::new())),
            logs: Arc::new(Mutex::new(vec!["System started...".to_string()])),
            my_name: format!("User_{}", my_id),
            my_id: my_id.clone(),
            crypto: Arc::new(Mutex::new(SecureChannel::new())),
        };
        
        let p_clone = Arc::clone(&state.peers);
        let m_clone = Arc::clone(&state.messages);
        let c_clone = Arc::clone(&state.crypto);
        let l_clone = Arc::clone(&state.logs);
        let id_clone = my_id.clone();
        let name_clone = state.my_name.clone();

        thread::spawn(move || Self::network_loop(id_clone, name_clone, p_clone, m_clone, l_clone, c_clone));
        
        state
    }

    fn add_log(logs: &Arc<Mutex<Vec<String>>>, msg: &str) {
        let mut l = logs.lock().unwrap();
        let time = Local::now().format("%H:%M:%S").to_string();
        l.push(format!("[{}] {}", time, msg));
        if l.len() > 50 { l.remove(0); }
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

    fn network_loop(
        my_id: String, my_name: String, 
        peers: Arc<Mutex<Vec<PeerInfo>>>, 
        messages: Arc<Mutex<Vec<Message>>>, 
        logs: Arc<Mutex<Vec<String>>>, 
        crypto: Arc<Mutex<SecureChannel>>
    ) {
        let socket = Self::create_udp_socket(DISCOVERY_PORT);
        let my_ip = Self::get_local_ip();
        Self::add_log(&logs, &format!("Listening on {}:{}", my_ip, DISCOVERY_PORT));

        let c_clone = Arc::clone(&crypto);
        let l_clone = Arc::clone(&logs);
        let m_clone = Arc::clone(&messages);
        
        thread::spawn(move || Self::tcp_listener(CHAT_PORT, m_clone, l_clone, c_clone));

        loop {
            let hello = Packet::Hello(PeerInfo { id: my_id.clone(), name: my_name.clone(), ip: my_ip.clone(), port: CHAT_PORT });
            let data = serde_json::to_string(&hello).unwrap();
            
            let _ = socket.send_to(data.as_bytes(), "255.255.255.255:5000");
            let _ = socket.send_to(data.as_bytes(), "127.0.0.1:5000");

            thread::sleep(Duration::from_secs(2));

            socket.set_read_timeout(Some(Duration::from_millis(100))).ok();
            let mut buf = [0; 65535];
            if let Ok((len, addr)) = socket.recv_from(&mut buf) {
                if let Ok(Packet::Hello(peer)) = serde_json::from_slice::<Packet>(&buf[..len]) {
                    if peer.id != my_id {
                        let mut p = peers.lock().unwrap();
                        if !p.iter().any(|x| x.id == peer.id) {
                            Self::add_log(&logs, &format!("Found: {} ({})", peer.name, addr.ip()));
                            p.push(peer);
                        }
                    }
                }
            }
        }
    }

    fn tcp_listener(
        port: u16, 
        messages: Arc<Mutex<Vec<Message>>>, 
        logs: Arc<Mutex<Vec<String>>>, 
        crypto: Arc<Mutex<SecureChannel>>
    ) {
        let listener = match TcpListener::bind(format!("0.0.0.0:{}", port)) {
            Ok(l) => {
                Self::add_log(&logs, &format!("TCP Listening on {}", port));
                l
            },
            Err(e) => { eprintln!("TCP Bind error: {}", e); return; }
        };

        for stream in listener.incoming() {
            if let Ok(mut stream) = stream {
                let peer_addr = stream.peer_addr().map(|a| a.ip().to_string()).unwrap_or("unknown".to_string());
                let mut buffer = [0; 65535];
                if let Ok(len) = stream.read(&mut buffer) {
                    if len > 0 {
                        if let Ok(enc_data) = serde_json::from_slice::<Vec<u8>>(&buffer[..len]) {
                            if let Ok(content) = crypto.lock().unwrap().decrypt(&enc_data) {
                                Self::add_log(&logs, &format!("Received: {}", content));
                                
                                let msg = Message {
                                    id: Uuid::new_v4().to_string()[..8].to_string(),
                                    sender_id: "remote_user".to_string(),
                                    sender_name: "User@".to_string() + &peer_addr,
                                    content,
                                    timestamp: Local::now().format("%H:%M:%S").to_string(),
                                };
                                messages.lock().unwrap().push(msg);
                            } else {
                                Self::add_log(&logs, "Decrypt failed");
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn get_peers(&self) -> Vec<PeerInfo> { self.peers.lock().unwrap().clone() }
    pub fn get_messages(&self) -> Vec<Message> { self.messages.lock().unwrap().clone() }
    pub fn get_logs(&self) -> Vec<String> { self.logs.lock().unwrap().clone() }
    
    pub fn send_message(&self, content: String) -> Result<(), String> {
        let msg = Message {
            id: Uuid::new_v4().to_string()[..8].to_string(),
            sender_id: self.my_id.clone(),
            sender_name: self.my_name.clone(),
            content: content.clone(),
            timestamp: Local::now().format("%H:%M:%S").to_string(),
        };
        
        self.messages.lock().unwrap().push(msg);
        
        let encrypted = self.crypto.lock().unwrap().encrypt(&content);
        let data = serde_json::to_string(&encrypted).unwrap();
        
        Self::add_log(&self.logs, "Broadcasting message...");

        let peers = self.peers.lock().unwrap().clone();
        let mut sent_count = 0;
        
        for peer in &peers {
            let addr = format!("{}:{}", peer.ip, peer.port);
            if let Ok(mut stream) = TcpStream::connect(&addr) {
                if stream.write_all(data.as_bytes()).is_ok() {
                    sent_count += 1;
                }
            }
        }
        
        if sent_count == 0 && !peers.is_empty() {
            Err("No peers responded".to_string())
        } else {
            Ok(())
        }
    }
}

#[tauri::command]
fn get_peers(state: tauri::State<AppState>) -> Vec<PeerInfo> { state.get_peers() }
#[tauri::command]
fn get_messages(state: tauri::State<AppState>) -> Vec<Message> { state.get_messages() }
#[tauri::command]
fn get_logs(state: tauri::State<AppState>) -> Vec<String> { state.get_logs() }
#[tauri::command]
fn send_message(state: tauri::State<AppState>, content: String) -> Result<(), String> {
    state.send_message(content)
}
#[tauri::command]
fn get_my_id(state: tauri::State<AppState>) -> String { state.my_id.clone() }

fn main() {
    let state = AppState::new();
    println!("DCS Global Chat Started. ID: {}", state.my_id);
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(state)
        .invoke_handler(tauri::generate_handler![get_peers, get_messages, send_message, get_my_id, get_logs])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}