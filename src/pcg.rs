//! An implementation of a permuted congruential generator based on the reference implementation at <pcg-random.org>. This is designed to work as it is required
//! in BANANAPEEL, which is simply as a generator of numbers that can be run through efficiently.
//!
//! The majority of the code here is not fully mathematically understood by the implementor, and it has been humbly copied directly from the C implementation.

use getrandom::getrandom;

/// A permuted congruential generator, implemented as an infinite generator.
// Note that this has been validated using the following C code (adapted from the reference implementation by Melissa O'Neil):
//
// ```c
// #include <inttypes.h>
// #include <stdio.h>
//
// typedef struct { uint64_t state;  uint64_t inc; } pcg32_random_t;
//
// uint32_t pcg32_random_r(pcg32_random_t* rng)
// {
//     uint64_t oldstate = rng->state;
//     // Advance internal state
//     rng->state = oldstate * 6364136223846793005ULL + (rng->inc|1);
//     // Calculate output function (XSH RR), uses old state for max ILP
//     uint32_t xorshifted = ((oldstate >> 18u) ^ oldstate) >> 27u;
//     uint32_t rot = oldstate >> 59u;
//     return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
// }
//
// void pcg32_srandom_r(pcg32_random_t* rng, uint64_t initstate, uint64_t initseq)
// {
//     rng->state = 0U;
//     rng->inc = (initseq << 1u) | 1u;
//     pcg32_random_r(rng);
//     rng->state += initstate;
//     pcg32_random_r(rng);
// }
//
// int main() {
//     pcg32_random_t rng = { 0, 0 };
//     pcg32_srandom_r(&rng, 6237633766001211634U, 13929184729078426727U);

//     printf("%u\n", pcg32_random_r(&rng));
//     printf("%u\n", pcg32_random_r(&rng));
//     printf("%u\n", pcg32_random_r(&rng));
// }
// ```
pub struct Pcg {
    state: u64,
    inc: u64,
}
impl Pcg {
    /// Creates a new PCG randomg number generator using seed values generated by a CSPRNG. Theoretically, this provides a cryptographically secure
    /// generator function that can be depended on if the outputs used are known only in random order, according to the BANANAPEEL specification.
    ///
    /// # Panics
    ///
    /// This will panic if it fails to get the pseudorandom numbers needed from the operating system's CSPRNG (e.g. `/dev/urandom` on Linux).
    /// Under the hood, this uses the [`getrandom`] function.
    pub fn new_seed() -> (u64, u64) {
        let mut init_state = [0u8; 8];
        let mut init_seq = [0u8; 8];
        getrandom(&mut init_state).expect("failed to get random initial state");
        getrandom(&mut init_seq).expect("failed to get random initial sequence");

        let init_state = u64::from_ne_bytes(init_state);
        let init_seq = u64::from_ne_bytes(init_seq);

        (init_state, init_seq)
    }

    /// Seeds a new PCG random number generator with the given initial state and sequence. Given the same values here, the generator will
    /// always produce the same output, which is important for BANANAPEEL decoding.
    pub fn from_seed(init_state: u64, init_seq: u64) -> Self {
        let mut pcg = Pcg {
            state: 0,
            inc: (init_seq << 1) | 1,
        };
        pcg.next();
        pcg.state = u64::wrapping_add(pcg.state, init_state);
        pcg.next();

        pcg
    }

    /// Gets the next pseudorandom number that the generator will produce. This will mutate the internal state, and is not implemented
    /// as an [`Iterator`] because the sequence will never be exhausted.
    pub fn next(&mut self) -> u32 {
        let oldstate = self.state;
        self.state = oldstate
            .wrapping_mul(6364136223846793005_u64)
            .wrapping_add(self.inc | 1);
        let xorshifted = (((oldstate >> 18) ^ oldstate) >> 27) as u32;
        let rot = (oldstate >> 59) as i32;

        (xorshifted >> rot) | (xorshifted << ((-rot) & 31))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Run as `cargo test -- --nocapture` to make sure the outputs are visible in stdout
    #[test]
    fn pcg_works() {
        let seed = Pcg::new_seed();
        let mut rng = Pcg::from_seed(seed.0, seed.1);
        println!("{}", rng.next());
        println!("{}", rng.next());
        println!("{}", rng.next());
    }
}
