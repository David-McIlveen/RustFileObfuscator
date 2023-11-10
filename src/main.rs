use std::fs;
use std::io;
use std::env;
use std::path::Path;
use std::io::prelude::*;
use std::io::BufReader;
use std::fs::{File, OpenOptions};
use std::str::FromStr;
use sha2::{Sha256, Digest};

fn main() {
    let args:Vec<String> = env::args().collect();
    if args.len() >= 2 {
        let command = args[1].to_uppercase();
        match command.as_str() {
            "CRV" => match attempt_to_create_valid_file(&args) {
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
            _ => println!("Command: \"{}\" does not exist.", command)
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
    fs::remove_file(temp_file_name);
    Ok(is_valid)
}