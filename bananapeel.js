// A decoder for the BANANAPEEL algorithm that can run in the browser. This is deliberately minimal, but it will decode any BANANAPEEL message produced
// by a compliant encoder. Since this runs in an interpreted language, do NOT expect this to be fast!

const key = {
    rng_init_state: BigInt("15073172615639268448"),
    rng_init_seq: BigInt("2504500227404849942"),
    base64_len: 20,
    noise_len: 22,
};
const partitions = [
    "1547ec9bc9621cc1252513f30c81b8516f3d248579eda3a2f53ffeeaf98a8260",
    "faae17a9f7d44142a650469b8131d3534756736247387349486476636d786b49"
];
const decoder = (key, partitions) => {
    // Utility functions for taking moduli in the 64-bit and 32-bit integer ranges
    const wrap64 = x => x % (18446744073709551615n + 1n);
    const wrap32 = x => x % (4294967295n + 1n)

    // Minimal PCG implementation with seeding
    let rng = {
        state: 0n,
        inc: wrap64((key.rng_init_seq << 1n) | 1n),
        next: function() {
            const oldstate = this.state;
            this.state = wrap64((oldstate * 6364136223846793005n) + (this.inc | 1n));
            const xorshifted = wrap32(((oldstate >> 18n) ^ oldstate) >> 27n);
            const rot = wrap32(oldstate >> 59n);
            return Number(wrap32((xorshifted >> rot) | (xorshifted << ((-rot) & 31n))));
        }
    };
    rng.next();
    rng.state = wrap64(rng.state + key.rng_init_state);
    rng.next();

    // Order and parse the partitions
    let next_idx = 0; // The next index to find
    while (next_idx < partitions.length) {
        let order_prefix = rng.next();
        let formatted_order_prefix = order_prefix.toString(16).padStart(8, '0');
        // NOTE: Not worth searching among those we've already parsed obviously
        for (let i = next_idx; i < partitions.length; i++) {
            if (partitions[i].startsWith(formatted_order_prefix)) {
                // Strip off the order prefix and the noise
                let data = partitions[i].substring(formatted_order_prefix.length);
                data = data.substring(key.noise_len);
                partitions[i] = data;
                // Now move that partition to the index we want it at
                [partitions[i], partitions[next_idx]] = [partitions[next_idx], partitions[i]];
                next_idx += 1;
            }
        }
    }

    // Reverse the hex encoding
    let hex = partitions.join("");
    // If there are an odd number of characters, we padded, so get rid of the last character until we handle the padding properly in
    // the base64 (otherwise we'll get an error)
    hex = hex.length % 2 !== 0 ? hex.substring(0, hex.length - 1) : hex;
    let base64 = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        const byte = parseInt(hex.substr(i, 2), 16);
        base64[i / 2] = byte;
    }

    // Remove the base 64 padding added to make the chunks even
    let base64_unpadded = base64.slice(0, key.base64_len);
    // Decode the base 64
    let base64_unpadded_str = new TextDecoder().decode(base64_unpadded);

    // JS needs a base64 *string* in order to perform native decoding (expects URL-safe)
    return atob(base64_unpadded_str);
}
console.log(decoder(key, partitions))
