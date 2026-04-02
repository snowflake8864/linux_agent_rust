use rand::RngCore;

pub struct Rc4 {
    s: [u8; 256],
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for i in 0..256 {
            s[i] = i as u8;
        }

        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }

        Self { s }
    }

    pub fn crypt(&mut self, data: &mut [u8]) {
        let mut i: u8 = 0;
        let mut j: u8 = 0;

        for byte in data.iter_mut() {
            i = i.wrapping_add(1);
            j = j.wrapping_add(self.s[i as usize]);
            self.s.swap(i as usize, j as usize);
            let k = self.s[(self.s[i as usize].wrapping_add(self.s[j as usize])) as usize];
            *byte ^= k;
        }
    }
}

pub struct CryptoManager {
    key: Vec<u8>,
}

impl CryptoManager {
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut rc4 = Rc4::new(&self.key);
        let mut ciphertext = plaintext.to_vec();
        rc4.crypt(&mut ciphertext);
        ciphertext
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let mut rc4 = Rc4::new(&self.key);
        let mut plaintext = ciphertext.to_vec();
        rc4.crypt(&mut plaintext);
        Ok(plaintext)
    }
}
