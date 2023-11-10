use std::fs;
use std::io;
use std::env;
use std::path::Path;
use std::io::prelude::*;
use std::io::BufReader;
use std::num::Wrapping;
use std::fs::{File, OpenOptions};
use std::str::FromStr;
use rand::Rng;
use sha2::{Sha256, Digest};

fn main() {
    let args:Vec<String> = env::args().collect();
    if args.len() >= 2 {
        let command = args[1].to_uppercase();
        match command.as_str() {
            "CVF" => match attempt_to_create_valid_file(&args) {
                Ok(s) => println!("{}", s),
                Err(e) => println!("{}", e)
            },
            "RVF" => match attempt_to_restore_valid_file(&args) {
                Ok(s) => println!("{}", s),
                Err(e) => println!("{}", e)
            },
            "VAL" => match attempt_to_validate_file(&args) {
                Ok(s) => println!("{}", s),
                Err(e) => println!("{}", e)
            },
            "ENC" => match attempt_to_encrypt_file(&args) {
                Ok(s) => println!("{}", s),
                Err(e) => println!("{}", e)
            },
            "DEC" => match attempt_to_dectrypt_file(&args) {
                Ok(s) => println!("{}", s),
                Err(e) => println!("{}", e)
            },
            "HELP" => {
                println!("CVF - Create Validateable File\nRVF - Restore Validateable File\nVAL - Validate File\nENC - Create an Encrypted File\nDEC - Decrypt an Encrypted File\nVEN - Create a Validateable Encrypted File\nDEN - Decrypt a Validateable Encrypted File");
            },
            _ => println!("Command: \"{}\" does not exist.\nEnter HELP for a list of the commands.", command)
        }
    } else {
        println!("No command entered.");
    }
    
    // match read_this_file("test.txt") {
    //     Ok(s) => println!("{s}"),
    //     Err(..) => println!("ERROR!")
    // }
    // match read_first_bytes::<32>("test.txt") {
    //     Ok(s) => println!("{:?}", [..s]),
    //     Err(..) => println!("ERROR!")
    // }
    // match hash_this_file("test.txt") {
    //     Ok(s) => println!("{s}"),
    //     Err(..) => println!("ERROR!")
    // }
    // match validate_file("temp/tem1/v.enc") {
    //     Ok(s) => if s {
    //         println!("File was valid!");
    //     } else {
    //         println!("File was invalid!");
    //     },
    //     Err(..) => println!("Could not validate file!")
    // }
    // match create_valid_file("test.txt", "temp/tem1/v.enc") {
    //     Ok(..) => println!("Validatable file created!"),
    //     Err(..) => println!("Could not create validatable file!")
    // }
}

fn attempt_to_create_valid_file(args:&Vec<String>) -> Result<&str, &str>{
    if args.len() >= 3 {
        let file_to_enter = args[2].clone();
        let file_to_save = {
            if args.len() > 4 {
                args[3].clone()
            } else {
                let mut file_temp = file_to_enter.clone();
                remove_file_extension(&mut file_temp);
                file_temp.push_str(".enc");
                file_temp
            }
        };
        match create_valid_file(&file_to_enter, &file_to_save) {
            Ok(..) => return Ok("Validatable file created."),
            Err(..) => return Err("Could not create validatable file.")
        }
    } else {
        return Err("No file entered.");
    }
}

fn remove_file_extension(file_name:&mut String){
    match file_name.rfind(".") {
        Some(i) => file_name.replace_range(i.., ""),
        None => ()
    }
}

fn attempt_to_restore_valid_file(args:&Vec<String>) -> Result<&str, &str> {
    if args.len() >= 3 {
        let file_to_unvalidate = args[2].clone();
        match validate_file(&file_to_unvalidate.as_str()) {
            Ok(..) => (),
            Err(..) => println!("WARNING! File being restored is not valid!")
        }
        let file_to_save_to = {
            if args.len() >= 4  {
                args[3].clone()
            } else {
                let mut temp_name: String = file_to_unvalidate.clone();
                remove_file_extension(&mut temp_name);
                temp_name.push_str(".temp");
                println!("- WARNING! No file to write to specified, a defualt template will be used.\n- You will need to rename the file with the proper extension!");
                temp_name
            }
        };
        match restore_valid_file(&file_to_unvalidate.as_str(), &file_to_save_to.as_str()) {
            Ok(..) => return Ok("Hashing data removed from file."),
            Err(..) => return Err("Hashing data could not be removed.")
        }
    } else {
        return Err("No file entered.");
    }
}

fn attempt_to_validate_file(args:&Vec<String>)  -> Result<&str, &str>{
    if args.len() >= 3 {
        match validate_file(args[2].as_str()) {
            Ok(s) => if s {
                return Ok("File was valid.");
            } else {
                return Ok("File was invalid.");
            },
            Err(..) => return Err("Could not validate file.")
        }
    } else {
        return Err("No file entered.");
    }
}

fn attempt_to_encrypt_file(args:&Vec<String>) -> Result<&str, &str> {
    match encrypt_file("temp1.txt", "temp1.enc", String::from("AAaa")) {
        Ok(..) => return Ok("Encrypted file made."),
        Err(..) => return Err("Could not encrypt file.")
    }
}

fn attempt_to_dectrypt_file(args:&Vec<String>) -> Result<&str, &str> {
    match dectyrpt_file("temp1.enc", "temp1.txt", String::from("AAaa")) {
        Ok(..) => return Ok("Encrypted file made."),
        Err(..) => return Err("Could not encrypt file.")
    }
}



fn read_this_file(file_name:&str) -> io::Result<String>{
    let f = File::open(file_name)?;
    let mut reader = BufReader::new(f);
    let mut buffer = String::new();

    reader.read_line(&mut buffer)?;
    Ok(buffer)
}

fn read_first_bytes<const LEN: usize>(file_name:&str) -> io::Result<[u8; LEN]>{
    let mut f = File::open(file_name)?;
    let mut buffer = [0; LEN];
    let _n = f.read(&mut buffer)?;
    Ok(buffer)
}

fn hash_this_file(file_name:&str) -> io::Result<String>{
    let mut file = File::open(file_name)?;

    let mut hasher = Sha256::new();

    let mut buffer = [0; 4096];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    
    Ok(format!("{:x}", hasher.finalize()))
}

fn create_valid_file(file_name:&str, new_file_name:&str) -> io::Result<()>{
    let mut new_valadatable_file = File::create(new_file_name)?;
    let empty_buffer = [0; 64];
    new_valadatable_file.write(&empty_buffer)?;
    let mut file = File::open(file_name)?;
    let mut buffer = [0; 4096];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        new_valadatable_file.write(&buffer[..bytes_read])?;
    }
    let mut final_file_add = OpenOptions::new().write(true).open(new_file_name)?;
    let hash_code = hash_this_file(new_file_name)?;
    let string_chars:Vec<char> = hash_code.chars().collect();
    let mut temp_buffer = [0; 64];
    for i in 0..string_chars.len() {
        temp_buffer[i] = string_chars[i] as u8;
    }
    final_file_add.write(&temp_buffer)?;
    Ok(())
}

fn restore_valid_file(file_name:&str, new_file_name:&str) -> io::Result<()> {
    let mut og_file = File::open(file_name)?;
    let mut new_file = File::create(new_file_name)?;
    let mut hash_buffer = [0; 64];
    let mut data_buffer = [0; 4096];
    og_file.read(&mut hash_buffer)?;
    loop {
        let bytes_read = og_file.read(&mut data_buffer)?;
        if bytes_read == 0 {
            break;
        }
        new_file.write(&data_buffer[..bytes_read])?;
    }
    Ok(())
}

fn validate_file(file_name:&str) -> io::Result<bool> {
    let hash_bytes = read_first_bytes::<64>(file_name)?;
    let path = Path::new(&file_name);
    let mut temp_file_name: String = String::from_str("").unwrap();
    match path.file_name() {
        Some(x) => temp_file_name = format!("~{}", x.to_str().unwrap()),
        None => ()
    }
    //println!("{}", temp_file_name);
    fs::copy(file_name, &temp_file_name)?;
    let mut temp_file = OpenOptions::new().write(true).open(temp_file_name.clone())?;
    let empty_buffer = [0; 64];
    temp_file.write(&empty_buffer)?;
    let hash_code = hash_this_file(&temp_file_name)?;
    let string_chars:Vec<char> = hash_code.chars().collect();
    let mut is_valid = true;
    let mut i = 0;
    while i < string_chars.len() - 1 && is_valid{
        is_valid = string_chars[i] as u8 == hash_bytes[i];
        i = i + 1;
    }
    fs::remove_file(temp_file_name)?;
    Ok(is_valid)
}

fn encrypt_file(file_to_encrypt_name:&str, file_out_name:&str, password:String) -> io::Result<()>{
    let mut rng = rand::thread_rng();
    let key: u128 = rng.gen();
    //println!("{:02x}", key);
    let key_bytes = key.to_be_bytes();
    //println!("{:#x?}", key_bytes);
    let password_bytes = password.as_bytes();
    //println!("{:#x?}", password_bytes);
    let mut file_to_encypt = File::open(file_to_encrypt_name)?;
    let mut file_out = File::create(file_out_name)?;
    file_out.write(&key_bytes)?;
    let mut data_buffer = [0; 4096];
    let mut key_offset:usize = password.len() % key_bytes.len();
    let mut pass_offset:usize = 0;
    loop {
        let bytes_read = file_to_encypt.read(&mut data_buffer)?;
        if bytes_read == 0 {
            break;
        } else {
            for i in 0..bytes_read{
                if password_bytes.len() != 0 {
                    let data_temp = Wrapping(data_buffer[i]) + Wrapping(password_bytes[pass_offset]);
                    data_buffer[i] = data_temp.0;
                    pass_offset += 1;
                    if pass_offset >= password_bytes.len(){
                        pass_offset = 0;
                    }
                }

                let data_temp = Wrapping(data_buffer[i]) + Wrapping(key_bytes[key_offset]);
                data_buffer[i] = data_temp.0;
                key_offset += 1;
                if key_offset >= key_bytes.len(){
                    key_offset = 0;
                }
            }
        }
        file_out.write(&data_buffer[..bytes_read])?;
    }
    println!("REMEMBER: Save your password as you won't be able to get it back Looser!");
    Ok(())
}

fn dectyrpt_file(file_to_decrypt_name:&str, file_out_name:&str, password:String) -> io::Result<()> {
    let mut file_to_decrypt = File::open(file_to_decrypt_name)?;
    let mut key_bytes = [0; 16];
    let password_bytes = password.as_bytes();
    let mut data_buffer = [0; 4096];
    let mut key_offset:usize = password.len() % key_bytes.len();
    let mut pass_offset:usize = 0;
    file_to_decrypt.read(&mut key_bytes)?;
    let mut file_out = File::create(file_out_name)?;
    loop {
        let bytes_read = file_to_decrypt.read(&mut data_buffer)?;
        if bytes_read == 0 {
            break;
        } else {
            for i in 0..bytes_read{
                if password_bytes.len() != 0 {
                    let data_temp = Wrapping(data_buffer[i]) - Wrapping(password_bytes[pass_offset]);
                    data_buffer[i] = data_temp.0;
                    pass_offset += 1;
                    if pass_offset >= password_bytes.len(){
                        pass_offset = 0;
                    }
                }

                let data_temp = Wrapping(data_buffer[i]) - Wrapping(key_bytes[key_offset]);
                data_buffer[i] = data_temp.0;
                key_offset += 1;
                if key_offset >= key_bytes.len(){
                    key_offset = 0;
                }
            }
        }
        file_out.write(&data_buffer[..bytes_read])?;
    }
    println!("REMEMBER: If you forgot your password or the file isn't coming out right, to bad - so sad.");
    Ok(())
}