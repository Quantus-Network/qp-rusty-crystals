//! Wrapper for DRBG (Deterministic Random Bit Generator) to match C reference implementation
//! Implements the exact same AES256_CTR_DRBG as the C reference code

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes256, Block};

/// DRBG context matching C implementation's AES256_CTR_DRBG_struct
struct DrbgCtx {
    key: [u8; 32],
    v: [u8; 16],
    reseed_counter: u64,
}

/// Global DRBG context (matching C implementation's global state)
static mut DRBG_CTX: Option<DrbgCtx> = None;

/// Increment a 16-byte counter in big-endian order (matching C implementation)
fn increment_counter(counter: &mut [u8; 16]) {
    for j in (0..16).rev() {
        if counter[j] == 0xff {
            counter[j] = 0x00;
        } else {
            counter[j] += 1;
            break;
        }
    }
}

/// AES256-ECB encryption (matching C AES256_ECB function)
fn aes256_ecb(key: &[u8; 32], input: &[u8; 16], output: &mut [u8; 16]) {
    let cipher = Aes256::new_from_slice(key).unwrap();
    let mut block = *Block::from_slice(input);
    cipher.encrypt_block(&mut block);
    output.copy_from_slice(block.as_slice());
}

/// AES256_CTR_DRBG_Update function (matching C implementation exactly)
fn aes256_ctr_drbg_update(provided_data: Option<&[u8; 48]>, key: &mut [u8; 32], v: &mut [u8; 16]) {
    let mut temp = [0u8; 48];
    
    // Generate 3 blocks (48 bytes) using AES256-ECB
    for i in 0..3 {
        increment_counter(v);
        let mut block_out = [0u8; 16];
        aes256_ecb(key, v, &mut block_out);
        temp[16 * i..16 * (i + 1)].copy_from_slice(&block_out);
    }
    
    // XOR with provided_data if present
    if let Some(data) = provided_data {
        for i in 0..48 {
            temp[i] ^= data[i];
        }
    }
    
    // Update Key and V
    key.copy_from_slice(&temp[0..32]);
    v.copy_from_slice(&temp[32..48]);
}

/// Initialize the DRBG with entropy input and optional personalization string
/// 
/// # Arguments
/// * `entropy_input` - 48 bytes of entropy
/// * `personalization_string` - Optional 48 bytes for personalization (XORed with entropy)
/// * `security_strength` - Security strength (should be 256 for AES256)
/// 
/// This matches the C function: `randombytes_init(entropy_input, personalization_string, security_strength)`
pub fn randombytes_init(
    entropy_input: &[u8],
    personalization_string: Option<&[u8]>,
    _security_strength: u32,
) -> Result<(), ()> {
    if entropy_input.len() != 48 {
        return Err(());
    }

    let mut seed_material = [0u8; 48];
    seed_material.copy_from_slice(entropy_input);

    // XOR with personalization string if provided (matching C implementation)
    if let Some(pers) = personalization_string {
        if pers.len() == 48 {
            for i in 0..48 {
                seed_material[i] ^= pers[i];
            }
        }
    }

    // Initialize DRBG context (matching C implementation)
    unsafe {
        let mut key = [0u8; 32];
        let mut v = [0u8; 16];
        key.fill(0x00);
        v.fill(0x00);
        
        // Call AES256_CTR_DRBG_Update with seed_material
        aes256_ctr_drbg_update(Some(&seed_material), &mut key, &mut v);
        
        DRBG_CTX = Some(DrbgCtx {
            key,
            v,
            reseed_counter: 1,
        });
    }

    Ok(())
}

/// Generate random bytes using the initialized DRBG
/// 
/// # Arguments
/// * `x` - Buffer to fill with random bytes
/// * `xlen` - Number of bytes to generate
/// 
/// This matches the C function: `randombytes(x, xlen)`
pub fn randombytes(x: &mut [u8], xlen: usize) -> Result<(), ()> {
    unsafe {
        if let Some(ref mut ctx) = DRBG_CTX {
            let mut i = 0;
            let mut remaining = xlen;
            
            while remaining > 0 {
                // Increment V
                increment_counter(&mut ctx.v);
                
                // Encrypt V to get block
                let mut block = [0u8; 16];
                aes256_ecb(&ctx.key, &ctx.v, &mut block);
                
                if remaining > 15 {
                    x[i..i + 16].copy_from_slice(&block);
                    i += 16;
                    remaining -= 16;
                } else {
                    x[i..i + remaining].copy_from_slice(&block[..remaining]);
                    remaining = 0;
                }
            }
            
            // Update DRBG state (matching C implementation)
            aes256_ctr_drbg_update(None, &mut ctx.key, &mut ctx.v);
            ctx.reseed_counter += 1;
            
            Ok(())
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drbg_deterministic() {
        let seed = [0x42u8; 48];
        
        // Initialize twice with same seed
        randombytes_init(&seed, None, 256).unwrap();
        let mut bytes1 = [0u8; 32];
        randombytes(&mut bytes1, 32).unwrap();
        
        randombytes_init(&seed, None, 256).unwrap();
        let mut bytes2 = [0u8; 32];
        randombytes(&mut bytes2, 32).unwrap();
        
        // Should produce same output
        assert_eq!(bytes1, bytes2);
    }
}
