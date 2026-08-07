// Copyright (c) 2026 Edison Lepiten / AIEONYX
// EdisonDB P3-M5 — ARPi (AXON Receptor Protocol Interface) integration
//
// ARPi is the AIEONYX protocol layer that carries data provenance metadata
// alongside every EdisonDB response. Receiving nodes verify the header to
// confirm data tier, audit chain continuity, and response integrity without
// trusting the transport.
//
// Header wire format (all fields fixed-width for deterministic serialization):
//   [1]  version   : u8  = 1
//   [1]  tier      : u8  = 0(Critical) | 1(Personal) | 2(Noise)
//   [8]  timestamp : u64 le
//   [4]  count     : u32 le  (number of records)
//   [32] audit_hash: [u8;32] (sealed audit-chain tail)
//   [32] seal      : [u8;32] (SHA-256 of all above fields)
// Total: 78 bytes

use crate::{AuditEntry, DataTier};

pub const ARPI_VERSION: u8 = 1;
pub const HEADER_SIZE: usize = 78;

/// ARPi data tier encoding
#[derive(Debug, Clone, PartialEq)]
pub enum ArpiTier {
    Critical = 0,
    Personal = 1,
    Noise = 2,
}

impl ArpiTier {
    pub fn from_data_tier(t: &DataTier) -> Self {
        match t {
            DataTier::Critical => Self::Critical,
            DataTier::Personal => Self::Personal,
            DataTier::Noise => Self::Noise,
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            Self::Critical => 0,
            Self::Personal => 1,
            Self::Noise => 2,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Critical),
            1 => Some(Self::Personal),
            2 => Some(Self::Noise),
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Personal => "personal",
            Self::Noise => "noise",
        }
    }
}

/// ARPi protocol header — 78 bytes
#[derive(Debug, Clone, PartialEq)]
pub struct ArpiHeader {
    pub version: u8,
    pub tier: ArpiTier,
    pub timestamp: u64,
    pub count: u32,
    pub audit_hash: [u8; 32],
    pub seal: [u8; 32],
}

impl ArpiHeader {
    /// Build a new header. Seal is computed automatically.
    pub fn new(tier: ArpiTier, timestamp: u64, count: u32, audit_hash: [u8; 32]) -> Self {
        let mut h = Self {
            version: ARPI_VERSION,
            tier,
            timestamp,
            count,
            audit_hash,
            seal: [0u8; 32],
        };
        h.seal = h.compute_seal();
        h
    }

    /// Build from a DataTier + audit log entries.
    pub fn from_audit(tier: &DataTier, entries: &[AuditEntry], count: u32) -> Self {
        let audit_hash = last_audit_hash(entries);
        let timestamp = crate::now_secs();
        Self::new(ArpiTier::from_data_tier(tier), timestamp, count, audit_hash)
    }

    /// Compute SHA-256 seal over (version || tier || timestamp || count || audit_hash).
    pub fn compute_seal(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(HEADER_SIZE - 32);
        buf.push(self.version);
        buf.push(self.tier.as_u8());
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.count.to_le_bytes());
        buf.extend_from_slice(&self.audit_hash);
        sha256(&buf)
    }

    /// Verify the seal is intact.
    pub fn verify(&self) -> bool {
        self.seal == self.compute_seal()
    }

    /// Serialize to 78-byte wire format.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        out[0] = self.version;
        out[1] = self.tier.as_u8();
        out[2..10].copy_from_slice(&self.timestamp.to_le_bytes());
        out[10..14].copy_from_slice(&self.count.to_le_bytes());
        out[14..46].copy_from_slice(&self.audit_hash);
        out[46..78].copy_from_slice(&self.seal);
        out
    }

    /// Deserialize from 78-byte wire format.
    pub fn from_bytes(b: &[u8; HEADER_SIZE]) -> Option<Self> {
        let version = b[0];
        if version != ARPI_VERSION {
            return None;
        }
        let tier = ArpiTier::from_u8(b[1])?;
        let timestamp = u64::from_le_bytes(b[2..10].try_into().ok()?);
        let count = u32::from_le_bytes(b[10..14].try_into().ok()?);
        let mut audit_hash = [0u8; 32];
        audit_hash.copy_from_slice(&b[14..46]);
        let mut seal = [0u8; 32];
        seal.copy_from_slice(&b[46..78]);
        Some(Self {
            version,
            tier,
            timestamp,
            count,
            audit_hash,
            seal,
        })
    }

    /// Hex string of audit_hash for logging / display.
    pub fn audit_hash_hex(&self) -> String {
        self.audit_hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    /// Hex string of seal for logging.
    pub fn seal_hex(&self) -> String {
        self.seal.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// ARPi response envelope — header + payload bytes
#[derive(Debug, Clone)]
pub struct ArpiResponse {
    pub header: ArpiHeader,
    pub payload: Vec<u8>,
}

impl ArpiResponse {
    pub fn new(header: ArpiHeader, payload: Vec<u8>) -> Self {
        Self { header, payload }
    }

    /// Serialize: [78-byte header][payload]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        out.extend_from_slice(&self.header.to_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Deserialize: first 78 bytes = header, rest = payload.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < HEADER_SIZE {
            return None;
        }
        let hdr_bytes: &[u8; HEADER_SIZE] = data[..HEADER_SIZE].try_into().ok()?;
        let header = ArpiHeader::from_bytes(hdr_bytes)?;
        let payload = data[HEADER_SIZE..].to_vec();
        Some(Self { header, payload })
    }

    /// Verify the header seal.
    pub fn verify(&self) -> bool {
        self.header.verify()
    }

    /// Check if the tier requires owner-only access.
    pub fn requires_auth(&self) -> bool {
        self.header.tier != ArpiTier::Noise
    }
}

// ── ARPi error ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ArpiError {
    InvalidSeal,
    InvalidVersion(u8),
    InvalidTier(u8),
    TruncatedHeader,
    AuthRequired,
}

impl std::fmt::Display for ArpiError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::InvalidSeal => write!(f, "ARPi: seal verification failed"),
            Self::InvalidVersion(v) => write!(f, "ARPi: unsupported version {}", v),
            Self::InvalidTier(t) => write!(f, "ARPi: invalid tier {}", t),
            Self::TruncatedHeader => write!(f, "ARPi: header truncated"),
            Self::AuthRequired => write!(f, "ARPi: authentication required for this tier"),
        }
    }
}

/// Validate a received ArpiResponse — verify seal and version.
pub fn validate(resp: &ArpiResponse) -> Result<(), ArpiError> {
    if resp.header.version != ARPI_VERSION {
        return Err(ArpiError::InvalidVersion(resp.header.version));
    }
    if !resp.header.verify() {
        return Err(ArpiError::InvalidSeal);
    }
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Return the sealed audit-chain tail, or zeros if the log is empty.
pub fn last_audit_hash(entries: &[AuditEntry]) -> [u8; 32] {
    entries
        .last()
        .map(|entry| entry.entry_hash)
        .unwrap_or([0u8; 32])
}

/// Sovereign SHA-256 (same implementation as axon_registry::hash — sovereign, no dep)
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for block in padded.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] =
            [h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, &v) in h.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}
