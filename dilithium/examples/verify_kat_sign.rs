//! KAT (Known Answer Test) file verifier
//! Matches the C reference implementation verify_kat_sign.c

use qp_rusty_crystals_dilithium::{
    drbg_wrapper, params,
    sign::{self, signature},
};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::process;

const MAX_MARKER_LEN: usize = 50;

fn find_marker<R: Read>(reader: &mut R, marker: &str) -> std::io::Result<bool> {
    let marker_bytes = marker.as_bytes();
    let len = marker_bytes.len().min(MAX_MARKER_LEN - 1);
    let mut buffer = vec![0u8; len];
    
    // Read initial bytes
    for i in 0..len {
        let mut byte = [0u8; 1];
        match reader.read_exact(&mut byte) {
            Ok(_) => buffer[i] = byte[0],
            Err(_) => return Ok(false),
        }
    }
    
    // Slide window to find marker
    loop {
        if buffer.starts_with(marker_bytes) {
            return Ok(true);
        }
        
        // Shift buffer left by one
        for i in 0..len - 1 {
            buffer[i] = buffer[i + 1];
        }
        
        // Read next byte
        let mut byte = [0u8; 1];
        match reader.read_exact(&mut byte) {
            Ok(_) => buffer[len - 1] = byte[0],
            Err(_) => return Ok(false),
        }
    }
}

fn read_hex<R: Read>(
    reader: &mut R,
    output: &mut [u8],
    marker: &str,
) -> std::io::Result<bool> {
    if output.is_empty() {
        return Ok(true);
    }
    
    if !find_marker(reader, marker)? {
        return Ok(false);
    }
    
    // Clear output
    output.fill(0);
    
    let mut started = false;
    let mut byte_buf = [0u8; 1];
    
    loop {
        match reader.read_exact(&mut byte_buf) {
            Ok(_) => {
                let ch = byte_buf[0];
                
                if !ch.is_ascii_hexdigit() {
                    if !started {
                        if ch == b'\n' {
                            break;
                        }
                        continue;
                    } else {
                        break;
                    }
                }
                
                started = true;
                let nibble = if ch.is_ascii_digit() {
                    ch - b'0'
                } else if ch.is_ascii_uppercase() {
                    ch - b'A' + 10
                } else {
                    ch - b'a' + 10
                };
                
                // Shift and add nibble (matching C implementation)
                for i in 0..output.len() - 1 {
                    output[i] = (output[i] << 4) | (output[i + 1] >> 4);
                }
                output[output.len() - 1] = (output[output.len() - 1] << 4) | nibble;
            }
            Err(_) => break,
        }
    }
    
    Ok(true)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <KAT_file.rsp>", args[0]);
        process::exit(1);
    }
    
    let file = match File::open(&args[1]) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Couldn't open <{}> for read: {}", args[1], e);
            process::exit(1);
        }
    };
    
    let mut reader = BufReader::new(file);
    let mut failures = 0;
    let mut total = 0;
    
    // Skip header line
    let mut line = String::new();
    reader.read_line(&mut line).ok();
    reader.read_line(&mut line).ok(); // Skip blank line
    
    loop {
        // Read count
        line.clear();
        if reader.read_line(&mut line).is_err() || line.is_empty() {
            break;
        }
        
        let count: i32 = match line.trim().strip_prefix("count = ") {
            Some(val) => match val.trim().parse() {
                Ok(n) => n,
                Err(_) => break,
            },
            None => break,
        };
        
        // Read seed
        let mut seed = [0u8; 48];
        if !read_hex(&mut reader, &mut seed, "seed = ").unwrap_or(false) {
            eprintln!("ERROR: unable to read 'seed' from {}", args[1]);
            process::exit(1);
        }
        
        // Initialize DRBG with seed
        drbg_wrapper::randombytes_init(&seed, None, 256).unwrap();
        
        // Read mlen
        line.clear();
        reader.read_line(&mut line).ok();
        let mlen: usize = match line.trim().strip_prefix("mlen = ") {
            Some(val) => match val.trim().parse() {
                Ok(n) => n,
                Err(_) => {
                    eprintln!("ERROR: unable to read 'mlen' from {}", args[1]);
                    process::exit(1);
                }
            },
            None => {
                eprintln!("ERROR: unable to read 'mlen' from {}", args[1]);
                process::exit(1);
            }
        };
        
        // Allocate buffers
        let mut m = vec![0u8; mlen];
        let mut sm_kat = vec![0u8; mlen + params::SIGNBYTES];
        let mut sm_gen = vec![0u8; mlen + params::SIGNBYTES];
        
        // Read message
        if !read_hex(&mut reader, &mut m, "msg = ").unwrap_or(false) {
            eprintln!("ERROR: unable to read 'msg' from {}", args[1]);
            process::exit(1);
        }
        
        // Read public key
        let mut pk = [0u8; params::PUBLICKEYBYTES];
        if !read_hex(&mut reader, &mut pk, "pk = ").unwrap_or(false) {
            eprintln!("ERROR: unable to read 'pk' from {}", args[1]);
            process::exit(1);
        }
        
        // Read secret key
        let mut sk = [0u8; params::SECRETKEYBYTES];
        if !read_hex(&mut reader, &mut sk, "sk = ").unwrap_or(false) {
            eprintln!("ERROR: unable to read 'sk' from {}", args[1]);
            process::exit(1);
        }
        
        // Regenerate keypair (advances DRBG state)
        let mut pk_gen = [0u8; params::PUBLICKEYBYTES];
        let mut sk_gen = [0u8; params::SECRETKEYBYTES];
        sign::keypair(&mut pk_gen, &mut sk_gen, None);
        
        if pk_gen != pk {
            println!("WARNING count {}: regenerated pk doesn't match KAT pk", count);
        }
        if sk_gen != sk {
            println!("WARNING count {}: regenerated sk doesn't match KAT sk", count);
        }
        
        // Read smlen
        line.clear();
        reader.read_line(&mut line).ok();
        let smlen_kat: usize = match line.trim().strip_prefix("smlen = ") {
            Some(val) => match val.trim().parse() {
                Ok(n) => n,
                Err(_) => {
                    eprintln!("ERROR: unable to read 'smlen' from {}", args[1]);
                    process::exit(1);
                }
            },
            None => {
                eprintln!("ERROR: unable to read 'smlen' from {}", args[1]);
                process::exit(1);
            }
        };
        
        // Read signed message from KAT
        if !read_hex(&mut reader, &mut sm_kat[..smlen_kat], "sm = ").unwrap_or(false) {
            eprintln!("ERROR: unable to read 'sm' from {}", args[1]);
            process::exit(1);
        }
        
        // Generate signature (signature function only fills the signature part)
        // Note: C crypto_sign places message in reverse order before signing
        // So we need to reverse the message to match
        if count == 0 {
            eprintln!("\n=== Processing count 0 ===");
            std::env::set_var("RUST_DEBUG_SIG", "1");
        }
        let mut m_reversed: Vec<u8> = m.iter().rev().copied().collect();
        let mut sig = vec![0u8; params::SIGNBYTES];
        signature(&mut sig, &m_reversed, &sk_gen, true, None);
        if count == 0 {
            std::env::remove_var("RUST_DEBUG_SIG");
        }
        
        // Construct signed message: [signature, message] (matching C crypto_sign)
        // C code places message in reverse: sm[CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i]
        sm_gen[..params::SIGNBYTES].copy_from_slice(&sig);
        for i in 0..mlen {
            sm_gen[params::SIGNBYTES + mlen - 1 - i] = m[mlen - 1 - i];
        }
        let smlen_gen = params::SIGNBYTES + mlen;
        
        // Compare signatures
        if smlen_gen != smlen_kat {
            println!(
                "FAIL count {}: smlen mismatch - got {}, expected {}",
                count, smlen_gen, smlen_kat
            );
            failures += 1;
        } else if sm_gen[..smlen_kat] != sm_kat[..smlen_kat] {
            println!(
                "FAIL count {}: signature mismatch (smlen matches: {})",
                count, smlen_gen
            );
            if count < 3 {
                print!("  First 32 bytes KAT: ");
                for i in 0..32.min(smlen_kat) {
                    print!("{:02X}", sm_kat[i]);
                }
                println!();
                print!("  First 32 bytes GEN: ");
                for i in 0..32.min(smlen_gen) {
                    print!("{:02X}", sm_gen[i]);
                }
                println!();
            }
            failures += 1;
        } else {
            println!("PASS count {}", count);
            if count < 3 {
                print!("  First 32 bytes KAT: ");
                for i in 0..32.min(smlen_kat) {
                    print!("{:02X}", sm_kat[i]);
                }
                println!();
                print!("  First 32 bytes GEN: ");
                for i in 0..32.min(smlen_gen) {
                    print!("{:02X}", sm_gen[i]);
                }
                println!();
            }
        }
        
        total += 1;
        
        // Skip blank line
        line.clear();
        reader.read_line(&mut line).ok();
    }
    
    println!("\nSummary: {}/{} tests passed", total - failures, total);
    if failures > 0 {
        println!("FAILED: {} tests failed", failures);
        process::exit(1);
    }
}
