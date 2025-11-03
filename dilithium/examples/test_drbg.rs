use qp_rusty_crystals_dilithium::drbg_wrapper;

fn main() {
    let mut seed = [0u8; 48];
    for i in 0..48 {
        seed[i] = i as u8;
    }
    
    drbg_wrapper::randombytes_init(&seed, None, 256).unwrap();
    
    let mut bytes = [0u8; 32];
    drbg_wrapper::randombytes(&mut bytes, 32).unwrap();
    
    print!("First 32 bytes: ");
    for i in 0..32 {
        print!("{:02X}", bytes[i]);
    }
    println!();
}

