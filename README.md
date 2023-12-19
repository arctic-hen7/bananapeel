# BANANAPEEL — A Slippery Obfuscation System

*Bananapeel* is a novel obfuscation algorithm that takes in text, typically the ciphertext of some encryption algorithm, and then encodes it in as a series of 'chunks' deliberately designed to appear identical to checksums. Usefully, these chunks can then be transmitted in any order, since each chunk has a unique prefix that denotes its order in the set of chunks. However, novelly, these prefixes are derived from a pseudo-random number generator, the seed of which becomes the key required to re-order the chunks.

Hence, not only does *Bananapeel* significantly obfuscate data to the point of its being almost unrecognisable, it also makes it infeasible to reconstruct data of a reasonable number of chunks without brute-forcing either every possible arrangement (which scales factorially with the number of chunks), or ever possible key (of which there are theoretically `2^192`, although in practice brute-forcing `2^128` partial keys provides enough information to complete an attack by statistical analysis). Since `35! > 2^128`, any data that encode to more than 35 chunks will therefore necessitate an attacker brute-forcing every possible key. Further, *Bananapeel* possesses the unique property that, because its decoding system requires sorting, if an incorrect key is tried, the order prefixes in the data will never be found from the incorrectly seeded PRNG, leading to an infinite loop on nearly all incorrect keys. Hence, a brute-force attacker would have to place a time limit on each decoding. Depending on the number of chunks, this can be up to or over a second on consumer-grade hardware for medium-length messages, but, even if this could be gotten down to one millisecond per key trial, this would still take `10^28` years if done in sequence.

Of course, all that assumes an attacker could not simply reverse two basic encoding processes and attempt to fit the chunks together like a jigsaw puzzle, which is why it is highly recommended that *Bananapeel* be used to encode the ciphertext of a real encryption algorithm, being used itself merely as an obfuscation tool, and for the convenience of enabling encoded chunks to be transmitted in any order. Further, since *Bananapeel* uniquely requires a key for decoding, using it in a scenario where a decryption key would already be required is far simpler than in one where key transmission is infeasible.

## Usage

To use *Bananapeel* through a CLI, you can install the Rust implementation, which gives you both encoding and decoding capability. However, if you only need to decode, then either the minified Python or JavaScript implementations may suit your needs better (for system and web applications respectively).

### CLI

To install, run

```sh
cargo install bananapeel
```

You can then run `bananapeel encode <plaintext-file>` and `bananapeel decode -k <key> <ciphertext-file>`. Due to the nature of the algorithm, providing custom keys is not supported, and a base64 key will be printed to stdout by the encoding command.

### JS

The JavaScript implementation at [`bananapeel.min.js`](bananapeel.min.js) exposes a single function, `bpDecode(key_str, partitions)`, which takes the string key as the first argument and an array of the output chunks, in any order of course, as the second. It will return the UTF-8 string of the plaintext.

This is designed to be used in a web browser or in NodeJS.

### Python

The Python implementation at [`bananapeel.min.py`](bananapeel.min.py) is a standalone script designed to be called like so:

```sh
cat <ciphertext-file> | python bananapeel.min.py "<key>"
```

It will then write the decoded plaintext to stdout. This is designed to be used with downloaded scripts or the like (e.g. `curl <some-script-url> | python bananapeel.min.py "<key>" | bash`)

## Parameters

The *Bananapeel* algorithm has several parameters, which can be helpful to understand when encoding.

**Output length:** the length of each output chunk as a number of hexadecimal characters, which can be used to make each chunk appear like a hash from some algorithm. For the same size of input data, a lower value here increases security by raising the number of permutations of the chunks, though the typical value is 64 (the length of a SHA256 hash, in hex characters).

**Minimum data per chunk:** the minimum number of hex characters per chunk which should be filled with actual data, the remnant being noise. This must be greater than the output length minus 8 (the first 8 characters are used for the order prefix). Note that the actual amount of noise will be randomly generated, and may produce less noisy chunks. A higher value here means a smaller number of output chunks, so fewer permutations to brute-force, reducing security a little. The default value is 32 (an even split or better between noise and data).

**Maximum skip chance:** the maximum chance as a float less than 1 that a given value from the PRNG will be skipped. For example, if this were `0.75`, then up to 75% of the order prefices from the PRNG will be skipped. Higher values here will mean ordering prefixes will be further apart, leading to decoding taking moderately longer. In the decoding process, every prefix is tried, and ignored if it isn't found, so a value of `0.75` would mean up to 75% of the tried prefixes would not appear. If an attacker tries to use an invalid key (e.g. in brute-forcing), they will probably never see enough valid prefixes (and only any by complete chance), so a time limit must be put on brute-forces. If this value is high enough, typical time limits may not be long enough to decode even with the correct key. In short, higher values of this parameter will lead to substantially greater security. The default is `0.75`.

## Repository contents

This repo contains a full Rust implementation of *Bananapeel*, the documentation for which is available [here](https://docs.rs/bananapeel), as well as a JavaScript implementation of a decoder *only*. Generally, you'll want to use the minified version, which is available in [`bananapeel.min.js`](bananapeel.min.js), and which exposes a single `bpDecode` function that takes a base64-encoded *Bananapeel* key as its first parameter, and an array of chunks as its second, returning the string message that was originally fed into *Bananapeel*.

In general, it is best to use the Rust implementation if you can, as it will be much faster and is probably far less error-prone (mainly because Rust has sane integer management, as opposed to JS' rather incomprehensible 53-bit precision), however the JS implementation is provided for use-cases such as [Cyst](https://github.com/arctic-hen7/cyst), for which this algorithm was originally designed.

Additionally, there is a highly minified and obfuscated Python implementation at [`bananapeel.min.py`](bananapeel.min.py), which is fewer than 800 characters long. This is designed to be used with shell scripts that can be read in through stdin.

## Security

*Bananapeel* is the result of a random thought that came to me while I was trying to obfuscate a Bash script, and has received no formal security audit whatsoever! If combined with a strong encryption algorithm, *Bananapeel* should not (to my limited knowledge) degrade the security of that algorithm, however it is not recommended to apply this algorithm to plaintext in any context in which security of any sort is required, as that would almost certainly end in tears.

## License

See [`LICENSE`](./LICENSE).
