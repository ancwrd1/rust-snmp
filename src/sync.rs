use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket},
    num::Wrapping,
    time::{Duration, Instant},
};

use crate::{
    handle_response, pdu, ResponseItem, ResponseItemInt, SnmpError, SnmpMessageType, SnmpPdu,
    SnmpResult, Value, BUFFER_SIZE,
};

/// Builder for synchronous SNMPv2 client
pub struct SyncSessionBuilder<A, S> {
    destination: A,
    community: Option<S>,
    timeout: Option<Duration>,
    req_id: i32,
}

impl<A, S> SyncSessionBuilder<A, S>
where
    A: ToSocketAddrs,
    S: AsRef<[u8]>,
{
    pub fn community(mut self, community: S) -> Self {
        self.community = Some(community);
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn req_id(mut self, req_id: i32) -> Self {
        self.req_id = req_id;
        self
    }

    pub fn build(self) -> io::Result<SyncSession> {
        SyncSession::new(self.destination, self.community, self.timeout, self.req_id)
    }
}

/// Synchronous SNMPv2 client.
pub struct SyncSession {
    destination: SocketAddr, // example: IPv4(127.0.0.1:161) or IPv6(_)
    socket: UdpSocket,
    community: Vec<u8>,
    req_id: Wrapping<i32>,
    send_pdu: pdu::Buf,
}

impl SyncSession {
    pub fn builder<A, S>(destination: A) -> SyncSessionBuilder<A, S>
    where
        S: AsRef<[u8]>,
    {
        SyncSessionBuilder {
            destination,
            community: None,
            timeout: None,
            req_id: 0,
        }
    }

    fn new<SA, T>(
        destination: SA,
        community: Option<T>,
        timeout: Option<Duration>,
        starting_req_id: i32,
    ) -> io::Result<Self>
    where
        SA: ToSocketAddrs,
        T: AsRef<[u8]>,
    {
        let destination_out: SocketAddr = destination
            .to_socket_addrs()?
            .next()
            .expect("empty list of socket addrs");

        let socket = Self::create_socket(destination_out, timeout, false)?;

        let community = community
            .map(|c| c.as_ref().into())
            .unwrap_or_else(|| b"public".to_vec());

        Ok(SyncSession {
            destination: destination_out,
            socket,
            community,
            req_id: Wrapping(starting_req_id),
            send_pdu: pdu::Buf::default(),
        })
    }

    fn create_socket(
        sock_addr: SocketAddr,
        timeout: Option<Duration>,
        broadcast: bool,
    ) -> io::Result<UdpSocket> {
        let socket = match sock_addr {
            SocketAddr::V4(_) => UdpSocket::bind((Ipv4Addr::new(0, 0, 0, 0), 0)),
            SocketAddr::V6(_) => UdpSocket::bind((Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0)),
        }?;
        socket.set_read_timeout(timeout)?;
        socket.set_broadcast(broadcast)?;
        Ok(socket)
    }

    fn send_and_recv(&self, pdu: &pdu::Buf) -> SnmpResult<ResponseItemInt> {
        if let Ok(_pdu_len) = self.socket.send_to(&pdu[..], self.destination) {
            Self::recv_one(&self.socket)
        } else {
            Err(SnmpError::SendError)
        }
    }

    fn recv_one(socket: &UdpSocket) -> SnmpResult<ResponseItemInt> {
        let mut buf_out = vec![0u8; BUFFER_SIZE];

        if let Ok((size, src_addr)) = socket.recv_from(&mut buf_out[..]) {
            unsafe {
                buf_out.set_len(size);
            }
            Ok(ResponseItemInt {
                address: src_addr.ip().to_string(),
                data: buf_out,
            })
        } else {
            Err(SnmpError::ReceiveError)
        }
    }

    pub fn get<T>(&mut self, names: &[T]) -> SnmpResult<SnmpPdu>
    where
        T: AsRef<[u32]>,
    {
        let req_id = self.req_id.0;
        self.req_id += Wrapping(1);

        pdu::build_get(self.community.as_slice(), req_id, names, &mut self.send_pdu)?;

        let response = self.send_and_recv(&self.send_pdu)?;

        handle_response(req_id, self.community.as_slice(), response.data.as_slice())
    }

    pub fn getnext(&mut self, name: &[u32]) -> SnmpResult<SnmpPdu> {
        let req_id = self.req_id.0;
        self.req_id += Wrapping(1);

        pdu::build_getnext(self.community.as_slice(), req_id, name, &mut self.send_pdu)?;

        let response = self.send_and_recv(&self.send_pdu)?;

        handle_response(req_id, self.community.as_slice(), response.data.as_slice())
    }

    pub fn get_all_responses<T>(
        &mut self,
        names: &[T],
        timeout: Duration,
    ) -> SnmpResult<Vec<ResponseItem>>
    where
        T: AsRef<[u32]>,
    {
        let req_id = self.req_id.0;
        self.req_id += Wrapping(1);

        let socket = Self::create_socket(self.destination, Some(timeout), true)
            .map_err(|_| SnmpError::SocketError)?;

        // send
        pdu::build_get(self.community.as_slice(), req_id, names, &mut self.send_pdu)?;
        socket
            .send_to(&self.send_pdu[..], self.destination)
            .map_err(|_| SnmpError::SendError)?;

        let ts1 = Instant::now();

        // recv all responses
        let mut vec1: Vec<ResponseItemInt> = Vec::new();
        loop {
            let response = Self::recv_one(&socket);
            if response.is_err() || ts1.elapsed() >= timeout {
                // skip any errors or delayed response
                break;
            }
            vec1.push(response.unwrap());
        }

        // parsing to SnmpPdu
        let mut vec2: Vec<ResponseItem> = Vec::new();
        for item in vec1.iter() {
            let r1 = handle_response(req_id, self.community.as_slice(), item.data.as_slice());
            if r1.is_ok() {
                vec2.push(ResponseItem {
                    address: item.address.clone(),
                    data: r1.unwrap(),
                })
            } else {
                // Error in response! - skip!
            }
        }

        Ok(vec2)
    }

    pub fn getbulk<T>(
        &mut self,
        names: &[T],
        non_repeaters: u32,
        max_repetitions: u32,
    ) -> SnmpResult<SnmpPdu>
    where
        T: AsRef<[u32]>,
    {
        let req_id = self.req_id.0;
        self.req_id += Wrapping(1);

        pdu::build_getbulk(
            self.community.as_slice(),
            req_id,
            names,
            non_repeaters,
            max_repetitions,
            &mut self.send_pdu,
        )?;

        let response = self.send_and_recv(&self.send_pdu)?;

        handle_response(req_id, self.community.as_slice(), response.data.as_slice())
    }

    /// # Panics if any of the values are not one of these supported types:
    ///   - `Boolean`
    ///   - `Null`
    ///   - `Integer`
    ///   - `OctetString`
    ///   - `ObjectIdentifier`
    ///   - `IpAddress`
    ///   - `Counter32`
    ///   - `Unsigned32`
    ///   - `Timeticks`
    ///   - `Opaque`
    ///   - `Counter64`
    pub fn set(&mut self, values: &[(&[u32], Value)]) -> SnmpResult<SnmpPdu> {
        let req_id = self.req_id.0;
        self.req_id += Wrapping(1);

        pdu::build_set(
            self.community.as_slice(),
            req_id,
            values,
            &mut self.send_pdu,
        )?;

        let response = self.send_and_recv(&self.send_pdu)?;
        let pdu_bytes = &response.data;

        let resp = SnmpPdu::from_bytes(pdu_bytes)?;
        if resp.message_type != SnmpMessageType::Response {
            return Err(SnmpError::AsnWrongType);
        }
        if resp.req_id != req_id {
            return Err(SnmpError::RequestIdMismatch);
        }
        if resp.community != self.community {
            return Err(SnmpError::CommunityMismatch);
        }
        Ok(resp)
    }
}
