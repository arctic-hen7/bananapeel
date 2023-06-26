# BANANAPEEL — A Slippery Obfuscation System

*Bananapeel* is a novel obfuscation algorithm that takes in text, typically the ciphertext of some encryption algorithm, and then encodes it in as a series of 'chunks' deliberately designed to appear identical to checksums. Usefully, these chunks can then be transmitted in any order, since each chunk has a unique prefix that denotes its order in the set of chunks. However, novelly, these prefixes are derived from a pseudo-random number generator, the seed of which becomes the key required to re-order the chunks.

Hence, not only does *Bananapeel* significantly obfuscate data to the point of its being almost unrecognisable, it also makes it infeasible to reconstruct data of a reasonable number of chunks without brute-forcing either every possible arrangement (which scales factorially with the number of chunks), or ever possible key (of which there are theoretically `2^192`, although in practice brute-forcing `2^128` partial keys provides enough information to complete an attack by statistical analysis). Since `35! > 2^128`, any data that encode to more than 35 chunks will therefore necessitate an attacker brute-forcing every possible key. Further, *Bananapeel* possesses the unique property that, because its decoding system requires sorting, if an incorrect key is tried, the order prefixes in the data will never be found from the incorrectly seeded PRNG, leading to an infinite loop on nearly all incorrect keys. Hence, a brute-force attacker would have to place a time limit on each decoding. Depending on the number of chunks, this can be up to or over a second on consumer-grade hardware for medium-length messages, but, even if this could be gotten down to one millisecond per key trial, this would still take `10^28` years if done in sequence.

Of course, all that assumes an attacker could not simply reverse two basic encoding processes and attempt to fit the chunks together like a jigsaw puzzle, which is why it is highly recommended that *Bananapeel* be used to encode the ciphertext of a real encryption algorithm, being used itself merely as an obfuscation tool, and for the convenience of enabling encoded chunks to be transmitted in any order. Further, since *Bananapeel* uniquely requires a key for decoding, using it in a scenario where a decryption key would already be required is far simpler than in one where key transmission is infeasible.

## Security

*Bananapeel* is the result of a random thought that came to me while I was trying to obfuscate a Bash script, and has received no formal security audit whatsoever! If combined with a strong encryption algorithm, *Bananapeel* should not (to my limited knowledge) degrade the security of that algorithm, however it is not recommended to apply this algorithm to plaintext in any context in which security of any sort is required, as that would almost certainly end in tears.

## License

See [`LICENSE`](LICENSE).
