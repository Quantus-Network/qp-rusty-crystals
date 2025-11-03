use std::fs::File;
use std::io::{BufRead, BufReader, Read};

fn find_marker<R: Read>(reader: &mut R, marker: &str) -> std::io::Result<bool> {
    let marker_bytes = marker.as_bytes();
    let len = marker_bytes.len().min(50 - 1);
    let mut buffer = vec![0u8; len];
    
    for i in 0..len {
        let mut byte = [0u8; 1];
        match reader.read_exact(&mut byte) {
            Ok(_) => buffer[i] = byte[0],
            Err(_) => return Ok(false),
        }
    }
    
    loop {
        if buffer.starts_with(marker_bytes) {
            return Ok(true);
        }
        
        for i in 0..len - 1 {
            buffer[i] = buffer[i + 1];
        }
        
        let mut byte = [0u8; 1];
        match reader.read_exact(&mut byte) {
            Ok(_) => buffer[len - 1] = byte[0],
            Err(_) => return Ok(false),
        }
    }
}

fn read_hex<R: Read>(reader: &mut R, output: &mut [u8], marker: &str) -> std::io::Result<bool> {
    if output.is_empty() {
        return Ok(true);
    }
    
    if !find_marker(reader, marker)? {
        return Ok(false);
    }
    
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
    let file = File::open("test_vectors/PQCsignKAT_Dilithium5.rsp").unwrap();
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    reader.read_line(&mut line).ok();
    reader.read_line(&mut line).ok();
    reader.read_line(&mut line).ok();
    
    let mut seed = [0u8; 48];
    read_hex(&mut reader, &mut seed, "seed = ").unwrap();
    
    print!("Read seed: ");
    for i in 0..48 {
        print!("{:02X}", seed[i]);
    }
    println!();
}
