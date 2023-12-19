# A decoder for the BANANAPEEL algorithm that can run in Python. This is deliberately minimal, but it will decode any BANANAPEEL message produced
# by a compliant encoder. Since this runs in an interpreted language, do NOT expect this to be fast!

import base64
import struct

def bp_decode(key_str, partitions):
    # Convert the key string into an actual key
    binary_key = base64.b64decode(key_str)
    key = {
        'rng_init_state': struct.unpack('<Q', binary_key[:8])[0],
        'rng_init_seq': struct.unpack('<Q', binary_key[8:16])[0],
        'base64_len': struct.unpack('<I', binary_key[16:20])[0],
        'noise_len': struct.unpack('<I', binary_key[20:24])[0],
    }

    # Utility functions for taking moduli in the 64-bit and 32-bit integer ranges
    def wrap64(x):
        return x % (18446744073709551615 + 1)

    def wrap32(x):
        return x % (4294967295 + 1)

    # Minimal PCG implementation with seeding
    class RNG:
        def __init__(self):
            self.state = 0
            self.inc = wrap64((key['rng_init_seq'] << 1) | 1)

        def next(self):
            oldstate = self.state
            self.state = wrap64((oldstate * 6364136223846793005) + (self.inc | 1))
            xorshifted = wrap32(((oldstate >> 18) ^ oldstate) >> 27)
            rot = wrap32(oldstate >> 59)
            return wrap32((xorshifted >> rot) | (xorshifted << ((-rot) & 31)))

    rng = RNG()
    rng.next()
    rng.state = wrap64(rng.state + key['rng_init_state'])
    rng.next()

    # Order and parse the partitions
    next_idx = 0  # The next index to find
    while next_idx < len(partitions):
        order_prefix = rng.next()
        formatted_order_prefix = format(order_prefix, '08x')
        # NOTE: Not worth searching among those we've already parsed obviously
        for i in range(next_idx, len(partitions)):
            if partitions[i].startswith(formatted_order_prefix):
                # Strip off the order prefix and the noise
                data = partitions[i][len(formatted_order_prefix):]
                data = data[key['noise_len']:]
                partitions[i] = data
                # Now move that partition to the index we want it at
                partitions[i], partitions[next_idx] = partitions[next_idx], partitions[i]
                next_idx += 1

    # Reverse the hex encoding
    hex_str = ''.join(partitions)
    # If there are an odd number of characters, we padded, so get rid of the last character until we handle the padding properly
    hex_str = hex_str[:-1] if len(hex_str) % 2 != 0 else hex_str

    base64_bytes = bytes.fromhex(hex_str)
    # Remove the base 64 padding added to make the chunks even
    base64_unpadded = base64_bytes[:key['base64_len']]
    # Decode the base 64
    base64_unpadded_str = base64.urlsafe_b64decode(base64_unpadded)

    # Python requires a base64 *bytes* in order to perform decoding (expects URL-safe)
    return base64_unpadded_str.decode('utf-8')
