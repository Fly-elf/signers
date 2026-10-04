/// One certificate of a signature's chain, as DER bytes.
///
/// The bytes are the certificate as `codesign` extracted it. They are not parsed: hand them to
/// an X.509 parser, or write them to a file to inspect with `openssl x509 -inform der`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    der: Vec<u8>,
}

impl Certificate {
    pub(crate) fn from_der(der: Vec<u8>) -> Self {
        Self { der }
    }

    /// The certificate in DER encoding.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// Takes the DER bytes, without copying them.
    pub fn into_der(self) -> Vec<u8> {
        self.der
    }
}
