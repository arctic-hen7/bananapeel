use bananapeel::{Bananapeel, Key};
use clap::{Parser, Subcommand};
use fmterr::fmterr;
use std::{fs, path::PathBuf};
use thiserror::Error;

fn main() {
    if let Err(err) = core() {
        eprintln!("{}", fmterr(&err));
        std::process::exit(1);
    }
}

fn core() -> Result<(), CliError> {
    let args = Args::parse();
    match args.command {
        Command::Encode {
            output_length,
            min_data_in_chunk,
            max_skip_chance,
            output,
            plaintext_file,
        } => {
            let bp = Bananapeel {
                output_len: output_length,
                min_data_in_chunk,
                max_value_skip_chance: max_skip_chance,
            };
            let plaintext = fs::read_to_string(plaintext_file)?;
            let (partitions, key) = bp.encode(&plaintext);
            let ciphertext = partitions.join("\n");

            if let Some(output) = output {
                fs::write(output, ciphertext)?;
            } else {
                println!("{ciphertext}");
            }
            eprintln!("Key: {}", key.to_string());
        }
        Command::Decode {
            key,
            ciphertext_file,
            output,
        } => {
            let key = Key::try_from(key)?;

            let ciphertext = fs::read_to_string(ciphertext_file)?;
            let mut partitions = ciphertext.lines().collect::<Vec<&str>>();

            let plaintext = Bananapeel::decode(&mut partitions, key)?;
            if let Some(output) = output {
                fs::write(output, plaintext)?;
            } else {
                println!("{plaintext}");
            }
        }
    }

    Ok(())
}

#[derive(Error, Debug)]
enum CliError {
    #[error(transparent)]
    KeyDecodeError(#[from] base64::DecodeError),
    #[error(transparent)]
    DecodeError(#[from] bananapeel::DecodeError),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

// --- Argument parsing ---

#[derive(Parser, Debug)]
struct Args {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Encode {
        /// The length of the output hex lines, which can be set to make them look like hashes
        #[arg(short = 'l', long, default_value = "64")]
        output_length: u32,
        /// The minimum number of characters in each chunk to devote to actual data, which must
        /// be less than the length of the output minus 8; higher values mean a shorter, but
        /// slightly less secure, output
        #[arg(long, default_value = "32")]
        min_data_in_chunk: u32,
        /// The maximum chance that a given order prefix will be skipped; higher values make
        /// decoding take longer, but significantly increase security
        #[arg(short = 's', long, default_value = "0.75")]
        max_skip_chance: f64,
        /// Where to put the output chunks (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// The file containing the plaintext.
        plaintext_file: PathBuf,
    },
    Decode {
        /// The base64 key for performing decoding
        #[arg(short, long)]
        key: String,
        /// The file containing the ciphertext
        ciphertext_file: PathBuf,
        /// Where to put the output plaintext (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}
