pub const KEY_SZ: usize = 16;

pub fn rand_bytes(buf: &mut [u8]) {
    #[cfg(unix)]
    {
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            if f.read_exact(buf).is_ok() {
                return;
            }
        }
        // xorshift64 fallback seeded from system time
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0xDEAD_BEEF_CAFE_1337);
        let mut x = seed ^ (std::process::id() as u64).wrapping_mul(0x9E3779B97F4A7C15);
        for b in buf.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x as u8;
        }
    }
    #[cfg(windows)]
    {
        extern "C" {
            fn rand_s(random_value: *mut u32) -> u32;
        }
        for b in buf.iter_mut() {
            let mut r: u32 = 0;
            unsafe { rand_s(&mut r); }
            *b = r as u8;
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let mut x = 0x123456789ABCDEFu64;
        for b in buf.iter_mut() {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            *b = x as u8;
        }
    }
}

pub fn rc4(key: &[u8], data: &mut [u8]) {
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j: usize = 0;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xFF;
        s.swap(i, j);
    }
    let (mut i, mut j) = (0usize, 0usize);
    for b in data.iter_mut() {
        i = (i + 1) & 0xFF;
        j = (j + s[i] as usize) & 0xFF;
        s.swap(i, j);
        *b ^= s[(s[i] as usize + s[j] as usize) & 0xFF];
    }
}

/// enc[i] = (key[i] + i) ^ b  where b is a random byte.
/// Returns (enc_key, hint_byte) where hint_byte = key[0].
/// The loader brute-forces b: (enc[0] ^ b) - 0 == key[0] == hint_byte.
pub fn obfuscate_key(key: &[u8]) -> (Vec<u8>, u8) {
    let mut xor = [0u8; 1];
    rand_bytes(&mut xor);
    let b = xor[0];
    let enc: Vec<u8> = key.iter()
        .enumerate()
        .map(|(i, &k)| k.wrapping_add(i as u8) ^ b)
        .collect();
    (enc, key[0])
}
