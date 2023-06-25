mod pcg;

use base64::{engine::general_purpose::URL_SAFE, DecodeError as Base64DecodeError, Engine};
use hex::FromHexError;
use pcg::Pcg;

/// The number of hexadecimal characters it takes to represent an unsigned 32-bit integer (i.e. a PCG output).
const U32_HEX_LENGTH: u32 = 8;

/// A key that can be used to decode a BANANAPEEL-encoded message.
#[derive(Debug)]
pub struct Key {
    /// The initial state of the PCG random number generator.
    rng_init_state: u64,
    /// The initial sequence of the PCG random number generator.
    rng_init_seq: u64,
    /// The length of the input string when encoded as base64 (needed to remove padding).
    base64_len: u64,
    /// The number of noise characters in each chunk.
    noise_len: u32,
}

/// The options used to encode/decode messages with BANANAPEEL. Generally you can instantiate this however you like,
/// however you should first understand how the lengths of BANANAPEEL output chunks work. Each chunk is comprised of
/// three parts like so:
///
/// ```text
/// <order-prefix; 8><noise; noise_len><encoded_chunk; x>
/// ```
///
/// In other words, every chunk first has a 8-character order prefix, then some noise, and finally an encoded chunk
/// takes up the rest of the space. Hence, the number of characters of encoded data that will be in each chunk will be
/// `output_len - noise_len - 8`, so you should be mindful to keep `noise_len` low enough that you do not end up with
/// too many chunks.
///
/// If you're unsure of how to initialise this manually, it is recommended that you use one of the pre-initialised options.
pub struct Bananapeel {
    /// The length of each output string as a number of hexadecimal characters.
    pub output_len: u32,
    /// The minimum number of characters in each chunk to devote to actual data. Note that this must be less than `output_len - 8`,
    /// since 8 characters are needed for the ordering prefixes. The actual number of noise characters will be randomly generated
    /// to be less than this value, but it will be kept uniform across all the chunks.
    pub min_data_in_chunk: u32,
    /// The maximum probability factor that a given order prefix from the PRNG will be skipped. This introduces a degree of
    /// randomness that makes certain attacks effectively impossible to implement, even with poor shuffling of the final
    /// output chunks. The actual probability factor will be randomly chosen to be some value less than or equal to this.
    ///
    /// Note that higher values here will make decoding take longer, which can be highly advantageous when working against an
    /// adversary who assumes a decode call with a correct key will time out after a certain known period, as this may force
    /// them to overlook a correct key in brute-forcing (if you happen to be facing adversaries who can wait for longer than
    /// the time the universe has existed for to decode your data).
    pub max_value_skip_chance: f64,
}
impl Bananapeel {
    /// Settings that make the output look like a series of SHA256 checksums.
    pub fn default_sha256() -> Self {
        Self {
            output_len: 64,
            min_data_in_chunk: 32,
            max_value_skip_chance: 0.75,
        }
    }

    /// Generates a new key and encodes the given input using it. This methodologically enforces the pattern that every distinct input
    /// must have a distinct key, since decoding is impossible without knowing a particular input-specific property (the length of the
    /// input in base 64). and for other reasons of cryptographic security.
    pub fn encode(&self, input: &str) -> (Vec<String>, Key) {
        // Make sure we have enough space to actually do anything
        assert!(self.output_len >= self.min_data_in_chunk + U32_HEX_LENGTH, "insufficient space for data in each chunk (please increase `output_len` or decrease `min_data_in_chunk`)");
        let max_noise_len = self.output_len - self.min_data_in_chunk - U32_HEX_LENGTH;

        // Initialise a supplemental RNG to be used generally (*not* the generator function!)
        let mut supplemental_rng = {
            let seed = Pcg::new_seed();
            Pcg::from_seed(seed.0, seed.1)
        };
        // Decide how many noise characters to use and how often to skip values
        let noise_len = supplemental_rng.next() % max_noise_len;
        // We turn the maximum chance into a number as a threshold; if a later random number is less than this threshold,
        // that will be skipped
        let value_skip_threshold =
            supplemental_rng.next() % (u32::MAX as f64 * self.max_value_skip_chance) as u32;

        // 1. Encode the input as base64
        let base64_encoded = URL_SAFE.encode(input);
        let base64_len = base64_encoded.len() as u64;
        // 2. Encode that as hexadecimal
        let hex_encoded = hex::encode(base64_encoded);
        // 3. Partition into strings of length `partition_len`
        let mut partitions =
            self.split_into_partitions(&hex_encoded, noise_len, &mut supplemental_rng);
        // 4. Create a PRNG that is deterministic based on its seed
        let rng_seed = Pcg::new_seed();
        let mut rng = Pcg::from_seed(rng_seed.0, rng_seed.1);
        // 5. For every chunk, generate an ordering prefix and prepend it (with a probability of skipping each value)
        for partition in partitions.iter_mut() {
            let order_prefix = loop {
                let possible_prefix = rng.next();
                // We'll skip if the value from the skip RNG is divisible by the given probability factor
                if supplemental_rng.next() < value_skip_threshold {
                    continue;
                } else {
                    break possible_prefix;
                }
            };
            // We may need to pad the order prefix to make sure it takes up the correct number of characters
            let noise = self.gen_noise(&mut supplemental_rng, noise_len);
            *partition = format!("{:08x}{}{}", order_prefix, noise, partition);
        }
        // 6. Shuffle the chunks (their ordering prefixes will preserve them if the key is known)
        // Inspired by `rand`'s `.shuffle()` method on slices
        for i in (1..partitions.len()).rev() {
            // Elements with indices greater than `i` have been locked in place
            partitions.swap(i, supplemental_rng.next() as usize % (i + 1));
        }

        let key = Key {
            base64_len,
            rng_init_state: rng_seed.0,
            rng_init_seq: rng_seed.1,
            noise_len,
        };

        (partitions, key)
    }
    /// Decodes the given message chunks using the given key. It is important to make sure that the options used for decoding
    /// are the same as those used for encoding, as this function only performs basic sanity checks on this! Attempting to decode
    /// with difference values to those used for encoding will lead to garbled output. The exception here is the `value_skip_chance`
    /// property, which does not need to be known (and ideally should be kept secret).
    ///
    /// **IMPORTANT:** Unlike many encryption algorithms, decoding a message using an invalid key will lead to one of two occurrences:
    /// either an infinite loop or garbled output. The former is more likely to occur because the output of the PRNG that is used as
    /// an ordering source will likely be unique for small (i.e. not in the hundreds of millions) numbers of chunks, so most outputs
    /// will simply not be found, leading the decoder to continue polling the PRNG indefinitely. Therefore, it is generally recommended
    /// that a time limit be placed on this function to prevent it from blocking the environment in which it is executed.
    pub fn decode(partitions: &mut [&str], key: Key) -> Result<String, DecodeError> {
        // 1. Re-seed the PRNG to use as a generator function
        let mut rng = Pcg::from_seed(key.rng_init_state, key.rng_init_seq);
        // 2. Going through the outputs of the generator, order the partitions according to the outputs of the generator (trying to find each one)
        let mut next_idx = 0; // The next index to find
        while next_idx < partitions.len() {
            let order_prefix = rng.next();
            let formatted_order_prefix = format!("{:08x}", order_prefix);
            // NOTE: Not worth searching among those we've already parsed obviously
            for i in next_idx..partitions.len() {
                if partitions[i].starts_with(&formatted_order_prefix) {
                    // Strip off the order prefix and the noise
                    let data = partitions[i].strip_prefix(&formatted_order_prefix).unwrap();
                    let data = &data[key.noise_len as usize..];
                    partitions[i] = &data;
                    // Now move that partition to the index we want it at
                    partitions.swap(i, next_idx);
                    next_idx += 1;
                }
            }
        }
        // 3. Reverse the hex encoding
        let hex = partitions.join("");
        // If there are an odd number of characters, we padded, so get rid of the last character until we handle the padding properly in
        // the base64 (otherwise we'll get an error)
        let hex = if hex.len() % 2 != 0 {
            &hex[0..hex.len() - 1]
        } else {
            hex.as_str()
        };
        let base64 = hex::decode(hex)?;
        // 4. Remove the base 64 padding added to make the chunks even
        let base64_unpadded = &base64[0..key.base64_len as usize];
        // 5. Decode the base 64
        let decoded = URL_SAFE.decode(base64_unpadded)?;
        let decoded_str = String::from_utf8(decoded).unwrap(); // This should never fail

        Ok(decoded_str)
    }

    /// Splits the given input into chunks of the appropriate partition size. This will perform padding, so this process is only reliably reversible
    /// if the length of the input string is known.
    ///
    /// # Panics
    ///
    /// This will panic if there is not enough space to place any characters in a given output chunk (i.e. if there is not more than a 8-character
    /// difference between `output_len` and `noise_len`).
    fn split_into_partitions(&self, input: &str, noise_len: u32, rng: &mut Pcg) -> Vec<String> {
        assert!(self.output_len - noise_len - U32_HEX_LENGTH > 0, "insufficient space to place characters in output chunks (please decrease noise or increase output length)");

        let mut chars = input.chars().collect::<Vec<_>>();
        // Pad the characters out to make sure we'll get the correct number of chunks (`.chunks_exact()` omits any remainder).
        // This is done using PRNG-generated random characters to make sure an attacker can't determine what the last chunk is
        // by looking for zero-padding or the like.
        let mut remainder = chars.len();
        while remainder > 0 {
            let rand_char = Self::gen_rand_hex_char(rng);
            chars.push(rand_char);
            remainder -= 1;
        }

        // As above, this will now have no remainder
        let partition_len = self.output_len - noise_len - U32_HEX_LENGTH;
        chars
            .chunks_exact(partition_len as usize)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<_>>()
    }
    /// Generates a certain number of "noise" characters using the given PRNG. Currently, this does not use a CSPRNG for speed, as it does not
    /// appear that one is needed, although that may change in future.
    fn gen_noise(&self, rng: &mut Pcg, noise_len: u32) -> String {
        let mut noise = String::new();
        for _ in 0..noise_len {
            let rand_char = Self::gen_rand_hex_char(rng);
            noise.push(rand_char);
        }

        noise
    }
    /// Generates a single random hexadecimal character.
    fn gen_rand_hex_char(rng: &mut Pcg) -> char {
        // We want to generate a hex character, so there are sixteen options
        let char_idx = rng.next() % 16;
        char::from_digit(char_idx as u32, 16).unwrap()
    }
}

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DecodeError {
    #[error(transparent)]
    HexDecodeError(#[from] FromHexError),
    #[error(transparent)]
    Base64DecodeError(#[from] Base64DecodeError),
}

#[cfg(test)]
mod tests {
    use crate::Bananapeel;
    use std::time::Instant;

    #[test]
    fn encoding_works() {
        let bp = Bananapeel::default_sha256();
        let msg = include_str!("../lorem.txt");

        let before_encode = Instant::now();
        let (encoded, key) = bp.encode(msg);
        let after_encode = Instant::now();

        for chunk in &encoded {
            assert_eq!(chunk.len(), 64);
        }
        println!("Key: {:#?}", key);
        std::fs::write("lorem_encoded.txt", encoded.join("\n")).unwrap();

        let mut encoded_slice = encoded.iter().map(|x| x.as_str()).collect::<Vec<_>>();

        let before_decode = Instant::now();
        let decoded = Bananapeel::decode(encoded_slice.as_mut_slice(), key);
        let after_decode = Instant::now();

        assert!(decoded.is_ok());
        assert_eq!(decoded.unwrap(), msg);

        println!(
            "Time to encode: {}ms",
            after_encode.duration_since(before_encode).as_millis()
        ); // ~4ms
        println!(
            "Time to decode: {}ms",
            after_decode.duration_since(before_decode).as_millis()
        ); // Highly dependent on noise length!
    }
}
