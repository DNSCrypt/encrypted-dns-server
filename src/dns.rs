use std::net::IpAddr;
use std::sync::Arc;

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};

use crate::dnscrypt_certs::*;
use crate::errors::*;

pub const DNS_MAX_HOSTNAME_SIZE: usize = 256;
pub const DNS_HEADER_SIZE: usize = 12;
pub const DNS_OFFSET_FLAGS: usize = 2;
pub const DNS_MAX_PACKET_SIZE: usize = 0x1600;

const DNS_MAX_INDIRECTIONS: usize = 16;
const DNS_FLAGS_TC: u16 = 1u16 << 9;
const DNS_FLAGS_QR: u16 = 1u16 << 15;
const DNS_FLAGS_RA: u16 = 1u16 << 7;
const DNS_FLAGS_RD: u16 = 1u16 << 8;
const DNS_FLAGS_CD: u16 = 1u16 << 4;
const DNS_OFFSET_QUESTION: usize = DNS_HEADER_SIZE;

pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_AAAA: u16 = 28;
pub const DNS_TYPE_OPT: u16 = 41;
pub const DNS_TYPE_TXT: u16 = 16;
pub const DNS_TYPE_HINFO: u16 = 13;
pub const DNS_CLASS_INET: u16 = 1;

pub const DNS_RCODE_SERVFAIL: u8 = 2;
pub const DNS_RCODE_NXDOMAIN: u8 = 3;
pub const DNS_RCODE_REFUSED: u8 = 5;

#[inline]
pub fn rcode(packet: &[u8]) -> u8 {
    packet[3] & 0x0f
}

#[inline]
pub fn set_rcode(packet: &mut [u8], rcode: u8) {
    packet[3] = (packet[3] & !0x0f) | rcode;
}

#[inline]
pub fn rcode_servfail(packet: &[u8]) -> bool {
    rcode(packet) == DNS_RCODE_SERVFAIL
}

#[inline]
pub fn set_rcode_servfail(packet: &mut [u8]) {
    set_rcode(packet, DNS_RCODE_SERVFAIL)
}

#[inline]
pub fn rcode_refused(packet: &[u8]) -> bool {
    rcode(packet) == DNS_RCODE_REFUSED
}

#[inline]
pub fn set_rcode_refused(packet: &mut [u8]) {
    set_rcode(packet, DNS_RCODE_REFUSED)
}

#[inline]
pub fn rcode_nxdomain(packet: &[u8]) -> bool {
    rcode(packet) == DNS_RCODE_NXDOMAIN
}

#[inline]
pub fn set_rcode_nxdomain(packet: &mut [u8]) {
    set_rcode(packet, DNS_RCODE_NXDOMAIN)
}

#[inline]
pub fn qdcount(packet: &[u8]) -> u16 {
    BigEndian::read_u16(&packet[4..])
}

#[inline]
pub fn ancount(packet: &[u8]) -> u16 {
    BigEndian::read_u16(&packet[6..])
}

fn ancount_inc(packet: &mut [u8]) -> Result<(), Error> {
    let mut ancount = ancount(packet);
    ensure!(ancount < 0xffff, "Too many answer records");
    ancount += 1;
    BigEndian::write_u16(&mut packet[6..], ancount);
    Ok(())
}

#[inline]
fn nscount(packet: &[u8]) -> u16 {
    BigEndian::read_u16(&packet[8..])
}

#[inline]
pub fn arcount(packet: &[u8]) -> u16 {
    BigEndian::read_u16(&packet[10..])
}

fn arcount_inc(packet: &mut [u8]) -> Result<(), Error> {
    let mut arcount = arcount(packet);
    ensure!(arcount < 0xffff, "Too many additional records");
    arcount += 1;
    BigEndian::write_u16(&mut packet[10..], arcount);
    Ok(())
}

#[inline]
fn arcount_clear(packet: &mut [u8]) -> Result<(), Error> {
    BigEndian::write_u16(&mut packet[10..], 0);
    Ok(())
}

#[inline]
pub fn an_ns_ar_count_clear(packet: &mut [u8]) {
    packet[6..12].iter_mut().for_each(|x| *x = 0);
}

#[inline]
pub fn tid(packet: &[u8]) -> u16 {
    BigEndian::read_u16(&packet[0..])
}

#[inline]
pub fn set_tid(packet: &mut [u8], tid: u16) {
    BigEndian::write_u16(&mut packet[0..], tid);
}

#[inline]
pub fn set_flags(packet: &mut [u8], flags: u16) {
    BigEndian::write_u16(&mut packet[DNS_OFFSET_FLAGS..], flags);
}

#[inline]
pub fn authoritative_response(packet: &mut [u8]) {
    let current_rd_cd_flags =
        BigEndian::read_u16(&packet[DNS_OFFSET_FLAGS..]) & (DNS_FLAGS_CD | DNS_FLAGS_RD);
    set_flags(packet, current_rd_cd_flags | DNS_FLAGS_QR | DNS_FLAGS_RA);
}

#[inline]
pub fn truncate(packet: &mut [u8]) {
    let current_flags = BigEndian::read_u16(&packet[DNS_OFFSET_FLAGS..]);
    BigEndian::write_u16(
        &mut packet[DNS_OFFSET_FLAGS..],
        current_flags | DNS_FLAGS_TC | DNS_FLAGS_QR | DNS_FLAGS_RA,
    );
}

#[inline]
pub fn is_response(packet: &[u8]) -> bool {
    BigEndian::read_u16(&packet[DNS_OFFSET_FLAGS..]) & DNS_FLAGS_QR == DNS_FLAGS_QR
}

#[inline]
pub fn is_truncated(packet: &[u8]) -> bool {
    BigEndian::read_u16(&packet[DNS_OFFSET_FLAGS..]) & DNS_FLAGS_TC == DNS_FLAGS_TC
}

pub fn qname(packet: &[u8]) -> Result<Vec<u8>, Error> {
    debug_assert!(std::usize::MAX > 0xffff);
    debug_assert!(DNS_MAX_HOSTNAME_SIZE > 0xff);
    let packet_len = packet.len();
    ensure!(packet_len > DNS_OFFSET_QUESTION, "Short packet");
    ensure!(qdcount(packet) == 1, "Unexpected query count");
    let mut offset = DNS_HEADER_SIZE;
    let mut qname = Vec::with_capacity(DNS_MAX_HOSTNAME_SIZE);
    loop {
        ensure!(offset < packet_len, "Short packet");
        match packet[offset] as usize {
            label_len if label_len & 0xc0 == 0xc0 => bail!("Indirections"),
            0 => {
                if qname.is_empty() {
                    qname.push(b'.')
                }
                break;
            }
            label_len => {
                ensure!(label_len < 0x40, "Long label");
                ensure!(packet_len - offset > 1, "Short packet");
                offset += 1;
                ensure!(packet_len - offset > label_len, "Short packet");
                if !qname.is_empty() {
                    qname.push(b'.')
                }
                ensure!(
                    qname.len() < DNS_MAX_HOSTNAME_SIZE - label_len,
                    "Name too long"
                );
                qname.extend_from_slice(&packet[offset..offset + label_len]);
                offset += label_len;
            }
        }
    }
    Ok(qname)
}

pub fn normalize_qname(packet: &mut [u8]) -> Result<(), Error> {
    debug_assert!(std::usize::MAX > 0xffff);
    debug_assert!(DNS_MAX_HOSTNAME_SIZE > 0xff);
    let packet_len = packet.len();
    ensure!(packet_len > DNS_OFFSET_QUESTION, "Short packet");
    ensure!(qdcount(packet) == 1, "Unexpected query count");
    let mut offset = DNS_HEADER_SIZE;
    loop {
        ensure!(offset < packet_len, "Short packet");
        match packet[offset] as usize {
            label_len if label_len & 0xc0 == 0xc0 => bail!("Indirections"),
            0 => {
                break;
            }
            label_len => {
                ensure!(label_len < 0x40, "Long label");
                ensure!(packet_len - offset > 1, "Short packet");
                offset += 1;
                ensure!(packet_len - offset > label_len, "Short packet");
                ensure!(
                    offset - DNS_HEADER_SIZE < DNS_MAX_HOSTNAME_SIZE - label_len,
                    "Name too long"
                );
                packet[offset..offset + label_len]
                    .iter_mut()
                    .for_each(|x| *x = x.to_ascii_lowercase());
                offset += label_len;
            }
        }
    }
    Ok(())
}

pub fn qname_tld(qname: &[u8]) -> &[u8] {
    qname.rsplit(|c| *c == b'.').next().unwrap_or_default()
}

pub fn recase_qname(packet: &mut [u8], qname: &[u8]) -> Result<(), Error> {
    debug_assert!(std::usize::MAX > 0xffff);
    let packet_len = packet.len();
    ensure!(packet_len > DNS_OFFSET_QUESTION, "Short packet");
    ensure!(qdcount(packet) == 1, "Unexpected query count");
    let qname_len = qname.len();
    let mut offset = DNS_HEADER_SIZE;
    let mut qname_offset = 0;
    loop {
        ensure!(offset < packet_len, "Short packet");
        match packet[offset] as usize {
            label_len if label_len & 0xc0 == 0xc0 => bail!("Indirections"),
            0 => {
                ensure!(
                    (qname_len == 1 && qname[0] == b'.') || qname_offset == qname_len,
                    "Unterminated reference qname"
                );
                break;
            }
            label_len => {
                ensure!(label_len < 0x40, "Long label");
                ensure!(packet_len - offset > 1, "Short packet");
                ensure!(qname_offset < qname_len, "Short reference qname");
                offset += 1;
                if qname_offset != 0 {
                    ensure!(qname[qname_offset] == b'.', "Non-matching reference qname");
                    qname_offset += 1;
                }
                ensure!(packet_len - offset > label_len, "Short packet");
                ensure!(
                    qname_len - qname_offset >= label_len,
                    "Short reference qname"
                );
                packet[offset..offset + label_len]
                    .iter_mut()
                    .zip(&qname[qname_offset..qname_offset + label_len])
                    .for_each(|(a, b)| {
                        debug_assert!(a.eq_ignore_ascii_case(b));
                        *a = *b
                    });
                offset += label_len;
                qname_offset += label_len;
            }
        }
    }
    Ok(())
}

fn skip_name(packet: &[u8], offset: usize) -> Result<usize, Error> {
    let packet_len = packet.len();
    ensure!(offset < packet_len - 1, "Short packet");
    let mut qname_len: usize = 0;
    let mut offset = offset;
    loop {
        let label_len = match packet[offset] as usize {
            label_len if label_len & 0xc0 == 0xc0 => {
                ensure!(packet_len - offset >= 2, "Incomplete offset");
                offset += 2;
                break;
            }
            label_len => label_len,
        };
        ensure!(label_len < 0x40, "Long label");
        ensure!(
            packet_len - offset - 1 > label_len,
            "Malformed packet with an out-of-bounds name"
        );
        qname_len += label_len + 1;
        ensure!(qname_len <= DNS_MAX_HOSTNAME_SIZE, "Name too long");
        offset += label_len + 1;
        if label_len == 0 {
            break;
        }
    }
    Ok(offset)
}

fn traverse_rrs<F: FnMut(usize) -> Result<(), Error>>(
    packet: &[u8],
    mut offset: usize,
    rrcount: usize,
    mut cb: F,
) -> Result<usize, Error> {
    let packet_len = packet.len();
    for _ in 0..rrcount {
        offset = skip_name(packet, offset)?;
        ensure!(packet_len - offset >= 10, "Short packet");
        let rdlen = BigEndian::read_u16(&packet[offset + 8..]) as usize;
        ensure!(
            packet_len - offset >= 10 + rdlen,
            "Record length would exceed packet length"
        );
        cb(offset)?;
        offset += 10;
        offset += rdlen;
    }
    Ok(offset)
}

fn traverse_rrs_mut<F: FnMut(&mut [u8], usize) -> Result<(), Error>>(
    packet: &mut [u8],
    mut offset: usize,
    rrcount: usize,
    mut cb: F,
) -> Result<usize, Error> {
    let packet_len = packet.len();
    for _ in 0..rrcount {
        offset = skip_name(packet, offset)?;
        ensure!(packet_len - offset >= 10, "Short packet");
        let rdlen = BigEndian::read_u16(&packet[offset + 8..]) as usize;
        ensure!(
            packet_len - offset >= 10 + rdlen,
            "Record length would exceed packet length"
        );
        cb(packet, offset)?;
        offset += 10;
        offset += rdlen;
    }
    Ok(offset)
}

pub fn min_ttl(packet: &[u8], min_ttl: u32, max_ttl: u32, failure_ttl: u32) -> Result<u32, Error> {
    let packet_len = packet.len();
    ensure!(packet_len > DNS_OFFSET_QUESTION, "Short packet");
    ensure!(packet_len <= DNS_MAX_PACKET_SIZE, "Large packet");
    ensure!(qdcount(packet) == 1, "No question");
    let mut offset = skip_name(packet, DNS_OFFSET_QUESTION)?;
    assert!(offset > DNS_OFFSET_QUESTION);
    ensure!(packet_len - offset > 4, "Short packet");
    offset += 4;
    let (ancount, nscount, arcount) = (ancount(packet), nscount(packet), arcount(packet));
    let rrcount = ancount as usize + nscount as usize + arcount as usize;
    let mut found_min_ttl = if rrcount > 0 { max_ttl } else { failure_ttl };

    offset = traverse_rrs(packet, offset, rrcount, |offset| {
        let qtype = BigEndian::read_u16(&packet[offset..]);
        let ttl = BigEndian::read_u32(&packet[offset + 4..]);
        if qtype != DNS_TYPE_OPT && ttl < found_min_ttl {
            found_min_ttl = ttl;
        }
        Ok(())
    })?;
    if found_min_ttl < min_ttl {
        found_min_ttl = min_ttl;
    }
    ensure!(packet_len == offset, "Garbage after packet");
    Ok(found_min_ttl)
}

pub fn set_ttl(packet: &mut [u8], ttl: u32) -> Result<(), Error> {
    let packet_len = packet.len();
    ensure!(packet_len > DNS_OFFSET_QUESTION, "Short packet");
    ensure!(packet_len <= DNS_MAX_PACKET_SIZE, "Large packet");
    ensure!(qdcount(packet) == 1, "No question");
    let mut offset = skip_name(packet, DNS_OFFSET_QUESTION)?;
    assert!(offset > DNS_OFFSET_QUESTION);
    ensure!(packet_len - offset > 4, "Short packet");
    offset += 4;
    let (ancount, nscount, arcount) = (ancount(packet), nscount(packet), arcount(packet));
    let rrcount = ancount as usize + nscount as usize + arcount as usize;
    offset = traverse_rrs_mut(packet, offset, rrcount, |packet, offset| {
        let qtype = BigEndian::read_u16(&packet[offset..]);
        if qtype != DNS_TYPE_OPT {
            BigEndian::write_u32(&mut packet[offset + 4..], ttl)
        }
        Ok(())
    })?;
    ensure!(packet_len == offset, "Garbage after packet");
    Ok(())
}

fn add_edns_section(packet: &mut Vec<u8>, max_payload_size: u16) -> Result<(), Error> {
    let opt_rr: [u8; 11] = [
        0,
        (DNS_TYPE_OPT >> 8) as u8,
        DNS_TYPE_OPT as u8,
        (max_payload_size >> 8) as u8,
        max_payload_size as u8,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    ensure!(
        DNS_MAX_PACKET_SIZE - packet.len() >= opt_rr.len(),
        "Packet would be too large to add a new record"
    );
    arcount_inc(packet)?;
    packet.extend(opt_rr);
    Ok(())
}

pub fn set_edns_max_payload_size(packet: &mut Vec<u8>, max_payload_size: u16) -> Result<(), Error> {
    let packet_len = packet.len();
    ensure!(packet_len > DNS_OFFSET_QUESTION, "Short packet");
    ensure!(packet_len <= DNS_MAX_PACKET_SIZE, "Large packet");
    ensure!(qdcount(packet) == 1, "No question");
    let mut offset = skip_name(packet, DNS_OFFSET_QUESTION)?;
    assert!(offset > DNS_OFFSET_QUESTION);
    ensure!(packet_len - offset >= 4, "Short packet");
    offset += 4;
    let (ancount, nscount, arcount) = (ancount(packet), nscount(packet), arcount(packet));
    offset = traverse_rrs(
        packet,
        offset,
        ancount as usize + nscount as usize,
        |_offset| Ok(()),
    )?;
    let mut edns_payload_set = false;
    traverse_rrs_mut(packet, offset, arcount as _, |packet, offset| {
        let qtype = BigEndian::read_u16(&packet[offset..]);
        if qtype == DNS_TYPE_OPT {
            ensure!(!edns_payload_set, "Duplicate OPT RR found");
            BigEndian::write_u16(&mut packet[offset + 2..], max_payload_size);
            edns_payload_set = true;
        }
        Ok(())
    })?;
    if edns_payload_set {
        return Ok(());
    }
    add_edns_section(packet, max_payload_size)?;
    Ok(())
}

pub fn serve_certificates<'t>(
    client_packet: &[u8],
    expected_qname: &str,
    dnscrypt_encryption_params_set: impl IntoIterator<Item = &'t Arc<DNSCryptEncryptionParams>>,
) -> Result<Option<Vec<u8>>, Error> {
    ensure!(client_packet.len() >= DNS_HEADER_SIZE, "Short packet");
    ensure!(qdcount(client_packet) == 1, "No question");
    ensure!(
        !is_response(client_packet),
        "Question expected, but got a response instead"
    );
    let offset = skip_name(client_packet, DNS_HEADER_SIZE)?;
    ensure!(client_packet.len() - offset >= 4, "Short packet");
    let qtype = BigEndian::read_u16(&client_packet[offset..]);
    let qclass = BigEndian::read_u16(&client_packet[offset + 2..]);
    if qtype != DNS_TYPE_TXT || qclass != DNS_CLASS_INET {
        return Ok(None);
    }
    let qname_v = qname(client_packet)?;
    let qname = std::str::from_utf8(&qname_v)?;
    if !qname.eq_ignore_ascii_case(expected_qname) {
        return Ok(None);
    }
    let mut packet = client_packet[..offset + 4].to_vec();
    an_ns_ar_count_clear(&mut packet);
    authoritative_response(&mut packet);
    let dnscrypt_encryption_params = dnscrypt_encryption_params_set
        .into_iter()
        .max_by_key(|x| x.dnscrypt_cert().ts_end())
        .ok_or_else(|| anyhow!("No certificates"))?;
    let cert_bin = dnscrypt_encryption_params.dnscrypt_cert().as_bytes();
    ensure!(cert_bin.len() <= 0xff, "Certificate too long");
    ancount_inc(&mut packet)?;
    packet.write_u16::<BigEndian>(0xc000 + DNS_HEADER_SIZE as u16)?;
    packet.write_u16::<BigEndian>(DNS_TYPE_TXT)?;
    packet.write_u16::<BigEndian>(DNS_CLASS_INET)?;
    packet.write_u32::<BigEndian>(DNSCRYPT_CERTS_RENEWAL)?;
    packet.write_u16::<BigEndian>(1 + cert_bin.len() as u16)?;
    packet.write_u8(cert_bin.len() as u8)?;
    packet.extend_from_slice(cert_bin);
    ensure!(packet.len() < DNS_MAX_PACKET_SIZE, "Packet too large");

    Ok(Some(packet))
}

pub fn serve_truncated_response(client_packet: Vec<u8>) -> Result<Vec<u8>, Error> {
    ensure!(client_packet.len() >= DNS_HEADER_SIZE, "Short packet");
    ensure!(qdcount(&client_packet) == 1, "No question");
    ensure!(
        !is_response(&client_packet),
        "Question expected, but got a response instead"
    );
    let offset = skip_name(&client_packet, DNS_HEADER_SIZE)?;
    let mut packet = client_packet;
    ensure!(packet.len() - offset >= 4, "Short packet");
    packet.truncate(offset + 4);
    an_ns_ar_count_clear(&mut packet);
    authoritative_response(&mut packet);
    truncate(&mut packet);
    Ok(packet)
}

pub fn qtype_qclass(packet: &[u8]) -> Result<(u16, u16), Error> {
    ensure!(packet.len() >= DNS_HEADER_SIZE, "Short packet");
    ensure!(qdcount(packet) == 1, "No question");
    let offset = skip_name(packet, DNS_HEADER_SIZE)?;
    ensure!(packet.len() - offset >= 4, "Short packet");
    let qtype = BigEndian::read_u16(&packet[offset..]);
    let qclass = BigEndian::read_u16(&packet[offset + 2..]);
    Ok((qtype, qclass))
}

fn parse_txt_rrdata<F: FnMut(&str) -> Result<(), Error>>(
    rrdata: &[u8],
    mut cb: F,
) -> Result<(), Error> {
    let rrdata_len = rrdata.len();
    let mut offset = 0;
    while offset < rrdata_len {
        let part_len = rrdata[offset] as usize;
        if part_len == 0 {
            break;
        }
        ensure!(rrdata_len - offset > part_len, "Short TXT RR data");
        offset += 1;
        let part_bin = &rrdata[offset..offset + part_len];
        let part = std::str::from_utf8(part_bin)?;
        cb(part)?;
        offset += part_len;
    }
    Ok(())
}

pub fn query_meta(packet: &mut Vec<u8>) -> Result<Option<String>, Error> {
    let packet_len = packet.len();
    ensure!(packet_len > DNS_OFFSET_QUESTION, "Short packet");
    ensure!(packet_len <= DNS_MAX_PACKET_SIZE, "Large packet");
    ensure!(qdcount(packet) == 1, "No question");
    let mut offset = skip_name(packet, DNS_OFFSET_QUESTION)?;
    assert!(offset > DNS_OFFSET_QUESTION);
    ensure!(packet_len - offset >= 4, "Short packet");
    offset += 4;
    let (ancount, nscount, arcount) = (ancount(packet), nscount(packet), arcount(packet));
    offset = traverse_rrs(
        packet,
        offset,
        ancount as usize + nscount as usize,
        |_offset| Ok(()),
    )?;
    let mut token = None;
    traverse_rrs(packet, offset, arcount as _, |mut offset| {
        let qtype = BigEndian::read_u16(&packet[offset..]);
        let qclass = BigEndian::read_u16(&packet[offset + 2..]);
        if qtype != DNS_TYPE_TXT || qclass != DNS_CLASS_INET {
            return Ok(());
        }
        let len = BigEndian::read_u16(&packet[offset + 8..]) as usize;
        offset += 10;
        ensure!(packet_len - offset >= len, "Short packet");
        let rrdata = &packet[offset..offset + len];
        parse_txt_rrdata(rrdata, |txt| {
            if txt.len() < 7 || !txt.starts_with("token:") {
                return Ok(());
            }
            ensure!(token.is_none(), "Duplicate token");
            let found_token = &txt[6..];
            let found_token = found_token.to_owned();
            token = Some(found_token);
            Ok(())
        })?;
        Ok(())
    })?;
    if token.is_some() {
        arcount_clear(packet)?;
        packet.truncate(offset);
    }
    Ok(token)
}

pub fn serve_nxdomain_response(client_packet: Vec<u8>) -> Result<Vec<u8>, Error> {
    ensure!(client_packet.len() >= DNS_HEADER_SIZE, "Short packet");
    ensure!(qdcount(&client_packet) == 1, "No question");
    ensure!(
        !is_response(&client_packet),
        "Question expected, but got a response instead"
    );
    let offset = skip_name(&client_packet, DNS_HEADER_SIZE)?;
    let mut packet = client_packet;
    ensure!(packet.len() - offset >= 4, "Short packet");
    packet.truncate(offset + 4);
    an_ns_ar_count_clear(&mut packet);
    authoritative_response(&mut packet);
    set_rcode_nxdomain(&mut packet);
    Ok(packet)
}

pub fn serve_blocked_response(client_packet: Vec<u8>) -> Result<Vec<u8>, Error> {
    ensure!(client_packet.len() >= DNS_HEADER_SIZE, "Short packet");
    ensure!(qdcount(&client_packet) == 1, "No question");
    ensure!(
        !is_response(&client_packet),
        "Question expected, but got a response instead"
    );
    let offset = skip_name(&client_packet, DNS_HEADER_SIZE)?;
    let mut packet = client_packet;
    ensure!(packet.len() - offset >= 4, "Short packet");
    packet.truncate(offset + 4);
    an_ns_ar_count_clear(&mut packet);
    authoritative_response(&mut packet);
    let hinfo_cpu = b"Query blocked";
    let hinfo_rdata = b"by the DNS server";
    let rdata_len = 1 + hinfo_cpu.len() + 1 + hinfo_rdata.len();
    ancount_inc(&mut packet)?;
    packet.write_u16::<BigEndian>(0xc000 + DNS_HEADER_SIZE as u16)?;
    packet.write_u16::<BigEndian>(DNS_TYPE_HINFO)?;
    packet.write_u16::<BigEndian>(DNS_CLASS_INET)?;
    packet.write_u32::<BigEndian>(60)?;
    packet.write_u16::<BigEndian>(rdata_len as _)?;
    packet.push(hinfo_cpu.len() as u8);
    packet.extend_from_slice(hinfo_cpu);
    packet.push(hinfo_rdata.len() as u8);
    packet.extend_from_slice(hinfo_rdata);
    Ok(packet)
}

pub fn serve_ip_response(client_packet: Vec<u8>, ip: IpAddr, ttl: u32) -> Result<Vec<u8>, Error> {
    ensure!(client_packet.len() >= DNS_HEADER_SIZE, "Short packet");
    ensure!(qdcount(&client_packet) == 1, "No question");
    ensure!(
        !is_response(&client_packet),
        "Question expected, but got a response instead"
    );
    let offset = skip_name(&client_packet, DNS_HEADER_SIZE)?;
    let mut packet = client_packet;
    ensure!(packet.len() - offset >= 4, "Short packet");
    packet.truncate(offset + 4);
    an_ns_ar_count_clear(&mut packet);
    authoritative_response(&mut packet);
    ancount_inc(&mut packet)?;
    packet.write_u16::<BigEndian>(0xc000 + DNS_HEADER_SIZE as u16)?;
    match ip {
        IpAddr::V4(ip) => {
            packet.write_u16::<BigEndian>(DNS_TYPE_A)?;
            packet.write_u16::<BigEndian>(DNS_CLASS_INET)?;
            packet.write_u32::<BigEndian>(ttl)?;
            packet.write_u16::<BigEndian>(4)?;
            packet.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            packet.write_u16::<BigEndian>(DNS_TYPE_AAAA)?;
            packet.write_u16::<BigEndian>(DNS_CLASS_INET)?;
            packet.write_u32::<BigEndian>(ttl)?;
            packet.write_u16::<BigEndian>(16)?;
            packet.extend_from_slice(&ip.octets());
        }
    };
    Ok(packet)
}
