# BANANAPEEL --- A Theoretical Encryption/Obfuscation System

BANANAPEEL is a novel algorithm that can be used to obfuscate data to the point where deobfuscation becomes computationally infeasible without knowledge of a certain key. It is designed to specifically produce a series of strings that are indistinguishable from the checksums that might be used to check the validity of a file, whcih can be transmitted in any order, and this is the critical property of the algorithm: because the strings can be shuffled in an arbitrary way, there are `n!` possible orders of `n` strings, meaning an attacker would have to try an infeasible number of possible orderings of the strings to reverse what is a fundamentally fairly basic encoding process.

## Security

BANANAPEEL is the result of a random thought that came to me while I was trying to obfuscate a Bash script, please do not rely on this for critical security measures! Generally, you should think of BANANAPEEL as an obfuscation algorithm that just happens to involve a key, and for which the algorithm itself can be made public. Applying BANANAPEEL to the ciphertext of a real encryption algorithm can be incredibly valuable, however, by making it seem indistinguishable from random metadata. The fact that each individual checksum-like string that the algorithm produces can then be transmitted in any order makes blocking a known-ciphertext message effectively impossible unless all the underlying string packets are blocked, which is highly likely to lead to false-positives when working with more than one million strings (as one often will with BANANAPEEL).

## License

See [`LICENSE`](LICENSE).
