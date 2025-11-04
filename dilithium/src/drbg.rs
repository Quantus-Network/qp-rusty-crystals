//! Wrapper for DRBG (Deterministic Random Bit Generator) to match C reference implementation
//! Implements the exact same AES256_CTR_DRBG as the C reference code

use crate::errors::DrbgError;
use aes::{
	cipher::{BlockEncrypt, KeyInit},
	Aes256, Block,
};

pub struct DRBG {
	key: [u8; 32],
	v: [u8; 16],
	reseed_counter: u64,
}

impl DRBG {
    /// Initialize the DRBG with entropy input and optional personalization string
    ///
    /// # Arguments
    /// * `entropy_input` - 48 bytes of entropy
    /// * `personalization_string` - Optional 48 bytes for personalization (XORed with entropy)
    ///
    /// This roughly matches the C function: `randombytes_init(entropy_input, personalization_string,
    /// security_strength)`
	pub fn new(
		entropy_input: &[u8],
		personalization_string: Option<&[u8]>,
	) -> Result<Self, DrbgError> {
		if entropy_input.len() != 48 {
			return Err(DrbgError::InvalidEntropyLength);
		}
	
		let mut seed_material = [0u8; 48];
		seed_material.copy_from_slice(entropy_input);

    	if let Some(pers) = personalization_string {
    		if pers.len() == 48 {
    			for i in 0..48 {
    				seed_material[i] ^= pers[i];
    			}
    		}
    	}
    
    	let mut key = [0u8; 32];
    	let mut v = [0u8; 16];
    	key.fill(0x00);
    	v.fill(0x00);
    
        let mut ctx = Self {
       		key,
       		v,
       		reseed_counter: 1,
       	};
        
    	ctx.aes256_ctr_drbg_update(Some(&seed_material));
    
    	Ok(ctx)
	}
	
	/// Generate random bytes using the initialized DRBG
    ///
    /// # Arguments
    /// * `x` - Buffer to fill with random bytes
    /// * `xlen` - Number of bytes to generate
    ///
    /// This matches the C function: `randombytes(x, xlen)`
    pub fn randombytes(&mut self, x: &mut [u8], xlen: usize) -> Result<(), DrbgError> {
    
    		let mut i = 0;
    		let mut remaining = xlen;
    
    		while remaining > 0 {
    			self.increment_counter();
    
    			let mut block = [0u8; 16];
    			self.aes256_ecb(&mut block);
    
    			if remaining > 15 {
    				x[i..i + 16].copy_from_slice(&block);
    				i += 16;
    				remaining -= 16;
    			} else {
    				x[i..i + remaining].copy_from_slice(&block[..remaining]);
    				remaining = 0;
    			}
    		}
    
    		self.aes256_ctr_drbg_update(None);
    		self.reseed_counter += 1;
    
    		Ok(())
    }

    fn increment_counter(&mut self) {
    	for j in (0..16).rev() {
    		if self.v[j] == 0xff {
    			self.v[j] = 0x00;
    		} else {
    			self.v[j] += 1;
    			break;
    		}
    	}
    }

    fn aes256_ecb(&mut self, output: &mut [u8; 16]) {
    	let cipher = Aes256::new_from_slice(&self.key).unwrap();
    	let mut block = *Block::from_slice(&self.v);
    	cipher.encrypt_block(&mut block);
    	output.copy_from_slice(block.as_slice());
    }
    
    fn aes256_ctr_drbg_update(&mut self, provided_data: Option<&[u8; 48]>) {
    	let mut temp = [0u8; 48];
        
    	// Generate 3 blocks (48 bytes) using AES256-ECB
    	for i in 0..3 {
    		self.increment_counter();
    		let mut block_out = [0u8; 16];
    		self.aes256_ecb(&mut block_out);
    		temp[16 * i..16 * (i + 1)].copy_from_slice(&block_out);
    	}
        
    	// XOR with provided_data if present
    	if let Some(data) = provided_data {
    		for i in 0..48 {
    			temp[i] ^= data[i];
    		}
    	}
        
    	// Update Key and V
    	self.key.copy_from_slice(&temp[0..32]);
    	self.v.copy_from_slice(&temp[32..48]);
    }    
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_drbg_deterministic() {
		let seed = [0x42u8; 48];
		let mut drbg1 = DRBG::new(&seed, None).unwrap();

		let mut bytes1 = [0u8; 32];
		drbg1.randombytes(&mut bytes1, 32).unwrap();

		let mut drbg2 = DRBG::new(&seed, None).unwrap();		
		let mut bytes2 = [0u8; 32];
		drbg2.randombytes(&mut bytes2, 32).unwrap();

		assert_eq!(bytes1, bytes2);
	}
}
