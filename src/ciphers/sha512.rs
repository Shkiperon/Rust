//! SHA-512

struct BufState {
    data: Vec<u8>,
    len: usize,
    total_len: usize,
    single: bool,
    total: bool,
}

pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut hash: [u8; 64] = [0; 64];

    let mut h: [u64; 8] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ];

    let k: [u64; 80] = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    ];

    let mut chunk: [u8; 64] = [0; 64];

    let mut state: BufState = BufState {
        data: (*data).to_owned(),
        len: data.len(),
        total_len: data.len(),
        single: false,
        total: false,
    };

    while calc_chunk(&mut chunk, &mut state) {
        let mut ah: [u64; 8] = h;
        let mut w: [u64; 16] = [0; 16];
        for i in 0..4 {
            for j in 0..16 {
                if i == 0 {
                    w[j] = ((chunk[j * 4] as u64) << 24)
                        | ((chunk[j * 4 + 1] as u64) << 16)
                        | ((chunk[j * 4 + 2] as u64) << 8)
                        | (chunk[j * 4 + 3] as u64);
                } else {
                    let s0 = (w[(j + 1) & 0xf].rotate_right(7) ^ w[(j + 1) & 0xf].rotate_right(18))
                        ^ (w[(j + 1) & 0xf] >> 3);
                    let s1 = w[(j + 14) & 0xf].rotate_right(17)
                        ^ w[(j + 14) & 0xf].rotate_right(19)
                        ^ (w[(j + 14) & 0xf] >> 10);
                    w[j] = w[j]
                        .wrapping_add(s0)
                        .wrapping_add(w[(j + 9) & 0xf])
                        .wrapping_add(s1);
                }

                let s1: u64 =
                    ah[4].rotate_right(6) ^ ah[4].rotate_right(11) ^ ah[4].rotate_right(25);
                let ch: u64 = (ah[4] & ah[5]) ^ (!ah[4] & ah[6]);
                let temp1: u64 = ah[7]
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(k[i << 4 | j])
                    .wrapping_add(w[j]);
                let s0: u64 =
                    ah[0].rotate_right(2) ^ ah[0].rotate_right(13) ^ ah[0].rotate_right(22);
                let maj: u64 = (ah[0] & ah[1]) ^ (ah[0] & ah[2]) ^ (ah[1] & ah[2]);
                let temp2: u64 = s0.wrapping_add(maj);

                ah[7] = ah[6];
                ah[6] = ah[5];
                ah[5] = ah[4];
                ah[4] = ah[3].wrapping_add(temp1);
                ah[3] = ah[2];
                ah[2] = ah[1];
                ah[1] = ah[0];
                ah[0] = temp1.wrapping_add(temp2);
            }
        }

        for i in 0..8 {
            h[i] = h[i].wrapping_add(ah[i]);
        }
        chunk = [0; 64];
    }

    for i in 0..8 {
        hash[i * 4] = (h[i] >> 24) as u8;
        hash[i * 4 + 1] = (h[i] >> 16) as u8;
        hash[i * 4 + 2] = (h[i] >> 8) as u8;
        hash[i * 4 + 3] = h[i] as u8;
    }

    hash
}

fn calc_chunk(chunk: &mut [u8; 64], state: &mut BufState) -> bool {
    if state.total {
        return false;
    }

    if state.len >= 64 {
        for x in chunk {
            *x = state.data[0];
            state.data.remove(0);
        }
        state.len -= 64;
        return true;
    }

    let remaining: usize = state.data.len();
    let space: usize = 64 - remaining;
    for x in chunk.iter_mut().take(state.data.len()) {
        *x = state.data[0];
        state.data.remove(0);
    }

    if !state.single {
        chunk[remaining] = 0x80;
        state.single = true;
    }

    if space >= 8 {
        let mut len = state.total_len;
        chunk[63] = (len << 3) as u8;
        len >>= 5;
        for i in 1..8 {
            chunk[(63 - i)] = len as u8;
            len >>= 8;
        }
        state.total = true;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /*#[test]
    fn empty() {
        assert_eq!(
            sha512(&Vec::new()),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );
    }*/

    #[test]
    fn ascii() {
        assert_eq!(
            sha512(&b"The quick brown fox jumps over the lazy dog".to_vec()),
            [
                0x07, 0xe5, 0x47, 0xd9, 0x58, 0x6f, 0x6a, 0x73, 0xf7, 0x3f,
                0xba, 0xc0, 0x43, 0x5e, 0xd7, 0x69, 0x51, 0x21, 0x8f, 0xb7,
                0xd0, 0xc8, 0xd7, 0x88, 0xa3, 0x09, 0xd7, 0x85, 0x43, 0x6b,
                0xbb, 0x64, 0x2e, 0x93, 0xa2, 0x52, 0xa9, 0x54, 0xf2, 0x39,
                0x12, 0x54, 0x7d, 0x1e, 0x8a, 0x3b, 0x5e, 0xd6, 0xe1, 0xbf,
                0xd7, 0x09, 0x78, 0x21, 0x23, 0x3f, 0xa0, 0x53, 0x8f, 0x3d,
                0xb8, 0x54, 0xfe, 0xe6
            ]
        )
    }

    #[test]
    fn ascii_avalanche() {
        assert_eq!(
            sha512(&b"The quick brown fox jumps over the lazy dog.".to_vec()),
            [
                0x91, 0xea, 0x12, 0x45, 0xf2, 0x0d, 0x46, 0xae, 0x9a, 0x03,
                0x7a, 0x98, 0x9f, 0x54, 0xf1, 0xf7, 0x90, 0xf0, 0xa4, 0x76,
                0x07, 0xee, 0xb8, 0xa1, 0x4d, 0x12, 0x89, 0x0c, 0xea, 0x77,
                0xa1, 0xbb, 0xc6, 0xc7, 0xed, 0x9c, 0xf2, 0x05, 0xe6, 0x7b,
                0x7f, 0x2b, 0x8f, 0xd4, 0xc7, 0xdf, 0xd3, 0xa7, 0xa8, 0x61,
                0x7e, 0x45, 0xf3, 0xc4, 0x63, 0xd4, 0x81, 0xc7, 0xe5, 0x86,
                0xc3, 0x9a, 0xc1, 0xed
            ]
        )
    }
}
