use rand::RngCore;

pub struct KeyManager {
    key: [u8; 32],
}

impl KeyManager {
    pub fn new() -> Self {
        let key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        Self { key }
    }

    pub fn get_key(&self) -> &[u8] {
        &self.key
    }

    pub fn load_key_from_config(key: &[u8]) -> Self {
        assert_eq!(key.len(), 32);
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key);
        Self { key: key_array }
    }
}
