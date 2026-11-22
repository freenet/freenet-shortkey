//! Types, derivation, encoding, verification and merge for the Freenet short-key resolver.
//!
//! A *short id* is `BLAKE3(DOMAIN || vk)[..16]`. A resolver contract is parameterised by the
//! short id; its state holds the full Ed25519 verifying key `vk` and, optionally, owner-signed
//! versioned application data. See the repository README for the protocol.

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use std::cmp::Ordering;
use std::fmt;

/// Domain separation prefix for deriving a short id from a verifying key.
pub const DERIVE_DOMAIN: &[u8] = b"freenet-shortkey/v1";
/// Domain separation prefix for the signed-data message.
pub const SIGN_DOMAIN: &[u8] = b"freenet-shortkey/v1/data";
/// Short id length in bytes (128 bits).
pub const SHORT_ID_LEN: usize = 16;
/// Ed25519 verifying key length in bytes.
pub const KEY_LEN: usize = 32;
/// Ed25519 signature length in bytes.
pub const SIG_LEN: usize = 64;
/// Maximum size of the optional application data in bytes.
pub const MAX_DATA_LEN: usize = 16 * 1024;
/// Version byte of the state, delta and summary encodings.
pub const WIRE_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Text is not valid base58, or decodes to the wrong length, or is not canonical.
    BadHandle(String),
    /// Bytes could not be parsed.
    Malformed(&'static str),
    /// The key is not a canonically encoded, torsion-free, non-identity Ed25519 point.
    BadKey,
    /// `BLAKE3(DOMAIN || vk)[..16]` does not equal the short id.
    BindingMismatch,
    /// Data exceeds `MAX_DATA_LEN`.
    DataTooLarge(usize),
    /// Signature over the data does not verify under `vk`.
    BadSignature,
    /// Two states with different keys cannot be merged.
    KeyMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadHandle(s) => write!(f, "bad handle: {s}"),
            Error::Malformed(s) => write!(f, "malformed encoding: {s}"),
            Error::BadKey => write!(
                f,
                "invalid Ed25519 public key (non-canonical, small-order or mixed-order)"
            ),
            Error::BindingMismatch => write!(f, "key does not hash to the short id"),
            Error::DataTooLarge(n) => write!(f, "data of {n} bytes exceeds {MAX_DATA_LEN}"),
            Error::BadSignature => write!(f, "data signature does not verify"),
            Error::KeyMismatch => write!(f, "states belong to different keys"),
        }
    }
}

impl std::error::Error for Error {}

/// Check that `vk` is an acceptable owner key: the canonical encoding of a point in the
/// prime-order subgroup that is not the identity. This rejects non-canonical encodings (y >= p,
/// or a set sign bit on x = 0), small-order points and mixed-order points `A + T`, so each
/// real key has exactly one accepted 32-byte form and hence exactly one handle.
pub fn validate_key(vk: &[u8; KEY_LEN]) -> Result<VerifyingKey, Error> {
    let point = CompressedEdwardsY(*vk).decompress().ok_or(Error::BadKey)?;
    if point.compress().to_bytes() != *vk || point.is_small_order() || !point.is_torsion_free() {
        return Err(Error::BadKey);
    }
    let key = VerifyingKey::from_bytes(vk).map_err(|_| Error::BadKey)?;
    if key.is_weak() {
        return Err(Error::BadKey);
    }
    Ok(key)
}

/// A 128-bit short id derived from an Ed25519 verifying key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ShortId(pub [u8; SHORT_ID_LEN]);

impl ShortId {
    /// `BLAKE3(DERIVE_DOMAIN || vk)[..16]`.
    pub fn derive(vk: &[u8; KEY_LEN]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(DERIVE_DOMAIN);
        h.update(vk);
        let mut out = [0u8; SHORT_ID_LEN];
        out.copy_from_slice(&h.finalize().as_bytes()[..SHORT_ID_LEN]);
        ShortId(out)
    }

    /// Parse the contract parameters (exactly 16 bytes).
    pub fn from_params(params: &[u8]) -> Result<Self, Error> {
        let arr: [u8; SHORT_ID_LEN] = params
            .try_into()
            .map_err(|_| Error::Malformed("parameters must be 16 bytes"))?;
        Ok(ShortId(arr))
    }

    /// Bitcoin-alphabet base58 text (21 or 22 characters).
    pub fn to_base58(&self) -> String {
        bs58::encode(self.0).into_string()
    }

    /// Strict inverse of [`to_base58`]: rejects bad characters, wrong length and any
    /// non-canonical spelling (so every id has exactly one accepted text form).
    pub fn from_base58(s: &str) -> Result<Self, Error> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| Error::BadHandle(e.to_string()))?;
        let arr: [u8; SHORT_ID_LEN] = bytes.as_slice().try_into().map_err(|_| {
            Error::BadHandle(format!("decodes to {} bytes, expected 16", bytes.len()))
        })?;
        let id = ShortId(arr);
        if id.to_base58() != s {
            return Err(Error::BadHandle("non-canonical spelling".into()));
        }
        Ok(id)
    }
}

impl fmt::Display for ShortId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base58())
    }
}

/// What a `?room=`-style parameter turned out to be, told apart by decoded length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Locator {
    Short(ShortId),
    Full([u8; KEY_LEN]),
}

/// Parse base58 text that is either a full 32-byte key or a 16-byte short id.
pub fn parse_locator(s: &str) -> Result<Locator, Error> {
    let bytes = bs58::decode(s)
        .into_vec()
        .map_err(|e| Error::BadHandle(e.to_string()))?;
    match bytes.len() {
        SHORT_ID_LEN => Ok(Locator::Short(ShortId::from_base58(s)?)),
        KEY_LEN => {
            let mut k = [0u8; KEY_LEN];
            k.copy_from_slice(&bytes);
            if bs58::encode(k).into_string() != s {
                return Err(Error::BadHandle("non-canonical spelling".into()));
            }
            Ok(Locator::Full(k))
        }
        n => Err(Error::BadHandle(format!(
            "decodes to {n} bytes, expected 16 or 32"
        ))),
    }
}

/// Owner-signed, versioned application data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedData {
    /// Monotonic revision; higher wins on merge.
    pub revision: u64,
    /// Application-defined schema/format number, independent of `revision`.
    pub format: u16,
    pub data: Vec<u8>,
    pub signature: [u8; SIG_LEN],
}

impl SignedData {
    /// The exact bytes the owner signs:
    /// `SIGN_DOMAIN || short_id || revision:u64 BE || format:u16 BE || len:u32 BE || data`.
    pub fn message(short_id: &ShortId, revision: u64, format: u16, data: &[u8]) -> Vec<u8> {
        let mut m = Vec::with_capacity(SIGN_DOMAIN.len() + SHORT_ID_LEN + 14 + data.len());
        m.extend_from_slice(SIGN_DOMAIN);
        m.extend_from_slice(&short_id.0);
        m.extend_from_slice(&revision.to_be_bytes());
        m.extend_from_slice(&format.to_be_bytes());
        m.extend_from_slice(&(data.len() as u32).to_be_bytes());
        m.extend_from_slice(data);
        m
    }

    /// Sign `data` with the owner's key.
    pub fn sign(
        key: &SigningKey,
        revision: u64,
        format: u16,
        data: Vec<u8>,
    ) -> Result<Self, Error> {
        use ed25519_dalek::Signer;
        if data.len() > MAX_DATA_LEN {
            return Err(Error::DataTooLarge(data.len()));
        }
        let id = ShortId::derive(key.verifying_key().as_bytes());
        let sig = key.sign(&Self::message(&id, revision, format, &data));
        Ok(SignedData {
            revision,
            format,
            data,
            signature: sig.to_bytes(),
        })
    }

    fn verify(&self, vk: &VerifyingKey, id: &ShortId) -> Result<(), Error> {
        if self.data.len() > MAX_DATA_LEN {
            return Err(Error::DataTooLarge(self.data.len()));
        }
        let sig = Signature::from_bytes(&self.signature);
        vk.verify_strict(
            &Self::message(id, self.revision, self.format, &self.data),
            &sig,
        )
        .map_err(|_| Error::BadSignature)
    }

    /// Total order used by merge: the greater value wins. Higher revision wins; at equal
    /// revision the lexicographically SMALLER signature wins (so smaller compares greater).
    /// Equal revision and equal signature means equal content (the signature covers it).
    pub fn precedence(&self, other: &SignedData) -> Ordering {
        self.revision
            .cmp(&other.revision)
            .then_with(|| other.signature.cmp(&self.signature))
    }
}

/// The resolver state: the full key, plus optional signed data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverState {
    pub vk: [u8; KEY_LEN],
    pub signed: Option<SignedData>,
}

impl ResolverState {
    /// The minimal mapping: key only, anyone can reconstruct it from the key.
    pub fn minimal(vk: [u8; KEY_LEN]) -> Self {
        ResolverState { vk, signed: None }
    }

    pub fn short_id(&self) -> ShortId {
        ShortId::derive(&self.vk)
    }

    /// Canonical encoding:
    /// `[1][vk:32][0]` or `[1][vk:32][1][revision:u64 BE][format:u16 BE][len:u32 BE][data][sig:64]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![WIRE_VERSION];
        out.extend_from_slice(&self.vk);
        match &self.signed {
            None => out.push(0),
            Some(s) => {
                out.push(1);
                out.extend_from_slice(&s.revision.to_be_bytes());
                out.extend_from_slice(&s.format.to_be_bytes());
                out.extend_from_slice(&(s.data.len() as u32).to_be_bytes());
                out.extend_from_slice(&s.data);
                out.extend_from_slice(&s.signature);
            }
        }
        out
    }

    /// Structural parse only. Call [`verify`](Self::verify) to check binding and signature.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader(bytes);
        if r.u8()? != WIRE_VERSION {
            return Err(Error::Malformed("unknown version"));
        }
        let vk = r.array::<KEY_LEN>()?;
        let signed = match r.u8()? {
            0 => None,
            1 => {
                let revision = u64::from_be_bytes(r.array()?);
                let format = u16::from_be_bytes(r.array()?);
                let len = u32::from_be_bytes(r.array()?) as usize;
                if len > MAX_DATA_LEN {
                    return Err(Error::DataTooLarge(len));
                }
                let data = r.take(len)?.to_vec();
                let signature = r.array::<SIG_LEN>()?;
                Some(SignedData {
                    revision,
                    format,
                    data,
                    signature,
                })
            }
            _ => return Err(Error::Malformed("bad data flag")),
        };
        if !r.0.is_empty() {
            return Err(Error::Malformed("trailing bytes"));
        }
        Ok(ResolverState { vk, signed })
    }

    /// Check the key binding to `id`, the key's validity, the size limit and, if present,
    /// the data signature. The minimal mapping needs no signature.
    pub fn verify(&self, id: &ShortId) -> Result<(), Error> {
        let vk = validate_key(&self.vk)?;
        if ShortId::derive(&self.vk) != *id {
            return Err(Error::BindingMismatch);
        }
        if let Some(s) = &self.signed {
            s.verify(&vk, id)?;
        }
        Ok(())
    }

    /// Merge `other` into `self`. Commutative, associative and idempotent over verified
    /// states of the same key; a minimal state never erases signed data.
    pub fn merge(&mut self, other: &ResolverState) -> Result<(), Error> {
        if self.vk != other.vk {
            return Err(Error::KeyMismatch);
        }
        match (&self.signed, &other.signed) {
            (_, None) => {}
            (None, Some(_)) => self.signed = other.signed.clone(),
            (Some(a), Some(b)) => {
                if b.precedence(a) == Ordering::Greater {
                    self.signed = other.signed.clone();
                }
            }
        }
        Ok(())
    }

    pub fn summary(&self) -> Summary {
        Summary {
            head: self
                .signed
                .as_ref()
                .map(|s| (s.revision, *blake3::hash(&s.signature).as_bytes())),
        }
    }

    /// Delta relative to a peer's summary: `None` (empty delta) when the peer already holds
    /// data at least as good as ours, else a state carrying our data. Conservative: at equal
    /// revision with a different digest we cannot tell who wins from a digest alone, so we
    /// send; the receiver's merge picks the winner.
    pub fn delta_for(&self, peer: &Summary) -> Option<ResolverState> {
        let ours = self.signed.as_ref()?;
        let send = match peer.head {
            None => true,
            Some((rev, digest)) => match ours.revision.cmp(&rev) {
                Ordering::Greater => true,
                Ordering::Less => false,
                Ordering::Equal => *blake3::hash(&ours.signature).as_bytes() != digest,
            },
        };
        send.then(|| self.clone())
    }
}

/// Digest-aware summary: the head revision and `BLAKE3(signature)` of the held data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub head: Option<(u64, [u8; 32])>,
}

impl Summary {
    /// `[1][0]` or `[1][1][revision:u64 BE][digest:32]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![WIRE_VERSION];
        match &self.head {
            None => out.push(0),
            Some((rev, d)) => {
                out.push(1);
                out.extend_from_slice(&rev.to_be_bytes());
                out.extend_from_slice(d);
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader(bytes);
        if r.u8()? != WIRE_VERSION {
            return Err(Error::Malformed("unknown version"));
        }
        let head = match r.u8()? {
            0 => None,
            1 => Some((u64::from_be_bytes(r.array()?), r.array::<32>()?)),
            _ => return Err(Error::Malformed("bad summary flag")),
        };
        if !r.0.is_empty() {
            return Err(Error::Malformed("trailing bytes"));
        }
        Ok(Summary { head })
    }
}

#[cfg(test)]
mod tests;

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < n {
            return Err(Error::Malformed("truncated"));
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }
}
