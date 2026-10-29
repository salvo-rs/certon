//! Controlled DNS transport for zone discovery and propagation tests.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use hickory_resolver::proto::op::{Message, OpCode};
use hickory_resolver::proto::rr::rdata::{CNAME, SOA, TXT};
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};

pub struct State {
    pub zone: String,
    /// 0 = normal, 1 = no SOA, 2 = CNAME to an unrelated SOA, 3 = drop queries.
    pub mode: AtomicU8,
    pub records: Mutex<HashMap<String, Vec<String>>>,
    pub queries: Mutex<Vec<(String, RecordType)>>,
    pub received: tokio::sync::Notify,
}

pub struct Server {
    pub address: String,
    pub state: Arc<State>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    pub async fn new(zone: &str) -> Self {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap().to_string();
        let state = Arc::new(State {
            zone: zone.to_lowercase(),
            mode: AtomicU8::new(0),
            records: Mutex::new(HashMap::new()),
            queries: Mutex::new(Vec::new()),
            received: tokio::sync::Notify::new(),
        });
        let shared = state.clone();
        let task = tokio::spawn(async move {
            let mut bytes = [0; 4096];
            loop {
                let (length, peer) = socket.recv_from(&mut bytes).await.unwrap();
                let query = Message::from_vec(&bytes[..length]).unwrap();
                let question = &query.queries[0];
                let name = question.name.to_ascii().to_lowercase();
                shared
                    .queries
                    .lock()
                    .unwrap()
                    .push((name.clone(), question.query_type));
                shared.received.notify_one();
                let mode = shared.mode.load(Ordering::SeqCst);
                if mode == 3 {
                    continue;
                }
                let mut response = Message::response(query.metadata.id, OpCode::Query);
                response.metadata.authoritative = true;
                response.metadata.recursion_desired = query.metadata.recursion_desired;
                response.metadata.recursion_available = true;
                response.queries = query.queries.clone();
                response.edns = query.edns.clone();
                match question.query_type {
                    RecordType::SOA if mode == 2 => {
                        let target = Name::from_ascii("unrelated.example.test.").unwrap();
                        response.answers.push(Record::from_rdata(
                            question.name.clone(),
                            60,
                            RData::CNAME(CNAME(target.clone())),
                        ));
                        response.answers.push(soa(target));
                    }
                    RecordType::SOA if mode == 0 && name == shared.zone => {
                        response.answers.push(soa(question.name.clone()));
                    }
                    RecordType::TXT => {
                        if let Some(values) = shared.records.lock().unwrap().get(&name) {
                            for value in values {
                                response.answers.push(Record::from_rdata(
                                    question.name.clone(),
                                    60,
                                    RData::TXT(TXT::new(vec![value.clone()])),
                                ));
                            }
                        }
                    }
                    _ => {}
                }
                socket
                    .send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        Self {
            address,
            state,
            task,
        }
    }
}

fn soa(name: Name) -> Record {
    Record::from_rdata(
        name,
        60,
        RData::SOA(SOA::new(
            Name::from_ascii("ns.example.test.").unwrap(),
            Name::from_ascii("hostmaster.example.test.").unwrap(),
            1,
            3600,
            60,
            86400,
            60,
        )),
    )
}
