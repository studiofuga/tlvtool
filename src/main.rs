use clap::{ArgGroup, Parser};
use iso7816_tlv::ber::{Tlv, Value};
use std::fs;
use std::io::{self, Read};

/// Parse BER-TLV encoded bytes from different input sources
#[derive(Debug, Parser)]
#[command(name = "tlv", version, about = "Parse BER-TLV from hex or binary input", long_about = None)]
#[command(group(
    ArgGroup::new("input")
        .args(["file", "binary", "hex"]) // at most one of these three should be used
        .multiple(false)
))]
struct Args {
    /// Read hex string from file path
    #[arg(short = 'f', long = "file", value_name = "PATH", conflicts_with = "binary")]
    file: Option<String>,

    /// Read raw binary bytes from file path
    #[arg(short = 'b', long = "binary", value_name = "PATH", conflicts_with = "file")]
    binary: Option<String>,

    /// Hex string provided directly on the command line (no flags)
    #[arg(value_name = "HEX", required = false)]
    hex: Option<String>,
}

fn main() {
    let args = Args::parse();

    // Decide the source of bytes according to the rules:
    // -b <path> → read raw bytes from file
    // -f <path> → read hex string from file and parse
    // <HEX>     → use the positional as hex string
    // (nothing) → read hex string from STDIN
    let bytes = match (&args.binary, &args.file, &args.hex) {
        (Some(bin_path), _, _) => match fs::read(bin_path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("Failed to read binary file '{}': {}", bin_path, e);
                std::process::exit(1);
            }
        },
        (None, Some(hex_path), _) => {
            let content = match fs::read_to_string(hex_path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to read hex file '{}': {}", hex_path, e);
                    std::process::exit(1);
                }
            };
            parse_hex_to_bytes(&content)
        }
        (None, None, Some(hex)) => parse_hex_to_bytes(hex),
        (None, None, None) => {
            // Read hex string from STDIN
            let mut buf = String::new();
            if let Err(e) = io::stdin().read_to_string(&mut buf) {
                eprintln!("Failed to read from stdin: {}", e);
                std::process::exit(1);
            }
            parse_hex_to_bytes(&buf)
        }
    };

    let stream = bytes.iter();
    loop {
        let (tlv, stream) = Tlv::parse(stream.as_slice());
        if let Err(e) = tlv {
            eprintln!("Failed to parse TLV: {}", e);
            break;
        }
        print_tlv(&tlv.unwrap(), 0);
        if stream.is_empty() {
            break;
        }
    }
}

fn parse_hex_to_bytes(input: &str) -> Vec<u8> {
    match hex_to_bytes(input) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error parsing hex string: {}", e);
            std::process::exit(1);
        }
    }
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    // Remove whitespace and convert to lowercase
    let hex: String = hex
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_lowercase();

    // Verify that the length is even
    if hex.len() % 2 != 0 {
        return Err("Hex string must have an even number of characters".to_string());
    }

    let mut bytes = Vec::new();
    for i in (0..hex.len()).step_by(2) {
        let hex_byte = &hex[i..i + 2];
        match u8::from_str_radix(hex_byte, 16) {
            Ok(byte) => bytes.push(byte),
            Err(_) => return Err(format!("Invalid hex character: {}", hex_byte)),
        }
    }

    Ok(bytes)
}

fn print_tlv(tlv: &Tlv, indent: usize) {
    let prefix = "  ".repeat(indent);

    println!("{}Tag: {:?}", prefix, tlv.tag());
    println!("{}Length: {}", prefix, tlv.length());

    match tlv.value() {
        Value::Primitive(data) => {
            println!("{}Value: \n{}", prefix, bytes_to_hex(&"  ".repeat(indent+2), data));
        }
        Value::Constructed(nested_tlvs) => {
            println!("{}Value: [Constructed]", prefix);
            for (i, nested_tlv) in nested_tlvs.iter().enumerate() {
                println!("{}  Nested TLV {}:", prefix, i + 1);
                print_tlv(nested_tlv, indent + 2);
            }
        }
    }
}

fn bytes_to_hex(prefix: &str, bytes: &[u8]) -> String {
    bytes.chunks(16).map(
        |chunk| {
            let hex_part = chunk.iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<String>>()
                .join(" ");
            let ascii_part = chunk.iter()
                .map(|b| if *b >= 32 && *b <= 126 { *b as char } else { '.' })
                .collect::<String>();
            let hex_width = 16 * 3 - 1; // 47
            format!("{}{:<hex_width$}    {}", prefix, hex_part, ascii_part, hex_width = hex_width)
        }
    ).collect::<Vec<String>>().join("\n")
}