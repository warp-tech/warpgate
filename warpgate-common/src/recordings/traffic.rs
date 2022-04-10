use std::net::Ipv4Addr;

use anyhow::Result;
use bytes::Bytes;
use packet::Builder;
use rand::Rng;
use tokio::time::Instant;
use tracing::*;
use warpgate_db_entities::Recording::RecordingKind;

use super::writer::RecordingWriter;
use super::Recorder;

pub struct TrafficRecorder {
    writer: RecordingWriter,
    started_at: Instant,
}

#[derive(Debug)]
pub struct TrafficConnectionParams {
    pub src_addr: Ipv4Addr,
    pub src_port: u16,
    pub dst_addr: Ipv4Addr,
    pub dst_port: u16,
}

impl TrafficRecorder {
    pub fn connection(&mut self, params: TrafficConnectionParams) -> ConnectionRecorder {
        ConnectionRecorder::new(params, self.writer.clone(), self.started_at)
    }
}

impl Recorder for TrafficRecorder {
    fn kind() -> RecordingKind {
        RecordingKind::Traffic
    }

    fn new(writer: RecordingWriter) -> Self {
        TrafficRecorder {
            writer,
            started_at: Instant::now(),
        }
    }
}

pub struct ConnectionRecorder {
    params: TrafficConnectionParams,
    seq_tx: u32,
    seq_rx: u32,
    writer: RecordingWriter,
    started_at: Instant,
}

impl ConnectionRecorder {
    fn new(params: TrafficConnectionParams, writer: RecordingWriter, started_at: Instant) -> Self {
        Self {
            params,
            writer,
            started_at,
            seq_rx: rand::thread_rng().gen(),
            seq_tx: rand::thread_rng().gen(),
        }
    }

    pub async fn write_connection_setup(&mut self) -> Result<()> {
        self.writer
            .write(&[
                0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0,
                101, 0, 0, 0,
            ])
            .await?;
        let init = self.tcp_init()?;
        self.write_packet(init.0).await?;
        self.write_packet(init.1).await?;
        self.write_packet(init.2).await?;
        Ok(())
    }

    async fn write_packet(&mut self, data: Bytes) -> Result<()> {
        let ms = Instant::now().duration_since(self.started_at).as_micros();
        self.writer
            .write(&u32::to_le_bytes((ms / 10u128.pow(6)) as u32))
            .await?;
        self.writer
            .write(&u32::to_le_bytes((ms % 10u128.pow(6)) as u32))
            .await?;
        self.writer
            .write(&u32::to_le_bytes(data.len() as u32))
            .await?;
        self.writer
            .write(&u32::to_le_bytes(data.len() as u32))
            .await?;
        self.writer.write(&data).await?;
        debug!("connection {:?} data {:?}", self.params, data);
        Ok(())
    }

    pub async fn write_rx(&mut self, data: &[u8]) -> Result<()> {
        debug!("connection {:?} data tx {:?}", self.params, data);
        let seq_rx = self.seq_rx;
        self.seq_rx = self.seq_rx.wrapping_add(data.len() as u32);
        self.write_packet(
            self.tcp_packet_rx(|b| Ok(b.sequence(seq_rx)?.payload(data)?.build()?.into()))?,
        )
        .await?;
        self.write_packet(self.tcp_packet_tx(|b| {
            Ok(b.sequence(self.seq_tx)?
                .acknowledgment(seq_rx + 1)?
                .flags(packet::tcp::Flags::ACK)?
                .build()?
                .into())
        })?)
        .await?;
        Ok(())
    }

    pub async fn write_tx(&mut self, data: &[u8]) -> Result<()> {
        debug!("connection {:?} data tx {:?}", self.params, data);
        let seq_tx = self.seq_tx;
        self.seq_tx = self.seq_tx.wrapping_add(data.len() as u32);
        self.write_packet(
            self.tcp_packet_tx(|b| Ok(b.sequence(seq_tx)?.payload(data)?.build()?.into()))?,
        )
        .await?;
        self.write_packet(self.tcp_packet_rx(|b| {
            Ok(b.sequence(self.seq_rx)?
                .acknowledgment(seq_tx + 1)?
                .flags(packet::tcp::Flags::ACK)?
                .build()?
                .into())
        })?)
        .await?;
        Ok(())
    }

    fn ip_packet_tx<F>(&self, f: F) -> Result<Bytes>
    where
        F: FnOnce(packet::ip::v4::Builder) -> Result<Bytes>,
    {
        f(packet::ip::v4::Builder::default()
            .protocol(packet::ip::Protocol::Tcp)?
            .source(self.params.src_addr)?
            .destination(self.params.dst_addr)?)
    }

    fn ip_packet_rx<F>(&self, f: F) -> Result<Bytes>
    where
        F: FnOnce(packet::ip::v4::Builder) -> Result<Bytes>,
    {
        f(packet::ip::v4::Builder::default()
            .protocol(packet::ip::Protocol::Tcp)?
            .source(self.params.dst_addr)?
            .destination(self.params.src_addr)?)
    }

    fn tcp_packet_tx<F>(&self, f: F) -> Result<Bytes>
    where
        F: FnOnce(packet::tcp::Builder) -> Result<Bytes>,
    {
        self.ip_packet_tx(|b| {
            f(b.tcp()?
                .source(self.params.src_port)?
                .destination(self.params.dst_port)?)
        })
    }

    fn tcp_packet_rx<F>(&self, f: F) -> Result<Bytes>
    where
        F: FnOnce(packet::tcp::Builder) -> Result<Bytes>,
    {
        self.ip_packet_rx(|b| {
            f(b.tcp()?
                .source(self.params.dst_port)?
                .destination(self.params.src_port)?)
        })
    }

    fn tcp_init(&mut self) -> Result<(Bytes, Bytes, Bytes)> {
        let seq_tx = self.seq_tx;
        self.seq_tx = self.seq_tx.wrapping_add(1);
        let seq_rx = self.seq_rx;
        self.seq_rx = self.seq_rx.wrapping_add(1);

        Ok((
            self.tcp_packet_tx(|b| {
                Ok(b.sequence(seq_tx)?
                    .flags(packet::tcp::Flags::SYN)?
                    .build()?
                    .into())
            })?,
            self.tcp_packet_rx(|b| {
                Ok(b.sequence(seq_rx)?
                    .acknowledgment(seq_tx + 1)?
                    .flags(packet::tcp::Flags::SYN | packet::tcp::Flags::ACK)?
                    .build()?
                    .into())
            })?,
            self.tcp_packet_tx(|b| {
                Ok(b.sequence(seq_tx + 1)?
                    .acknowledgment(seq_rx + 1)?
                    .flags(packet::tcp::Flags::ACK)?
                    .build()?
                    .into())
            })?,
        ))
    }
}
