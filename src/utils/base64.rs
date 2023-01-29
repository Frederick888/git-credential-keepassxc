use base64::{DecodeError, Engine};

pub fn encode<T: AsRef<[u8]>>(input: T) -> String {
    base64::engine::general_purpose::STANDARD.encode(input)
}
pub fn decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(input)
}
