# A decoder for the BANANAPEEL algorithm that can run in Python. This is deliberately minimal, but it will decode any BANANAPEEL message produced
# by a compliant encoder. Since this runs in an interpreted language, do NOT expect this to be fast!
#
# This code has deliberately been made extremely minimal and compressed.

import sys
import base64
import struct

PCG_MAGIC_MODULUS_1 = 18446744073709551615
PCG_MAGIC_MODULUS_2 = 4294967295

# Read the partitions from stdin
partitions = [line.strip() for line in sys.stdin.readlines()]
# Unpack the key string into its components
key = dict(zip(
    ['rng_init_state', 'rng_init_seq', 'base64_len', 'noise_len'],
    struct.unpack('<QQII', base64.b64decode(sys.argv[1])[:24])
))

# Utility function to handle modulus operation for different integer ranges
wrap = lambda x, limit: x % (limit + 1)

# Minimal PCG implementation with seeding
def rng_next(rng):
    oldstate = rng['state']
    rng['state'] = wrap(oldstate * 6364136223846793005 + (rng['inc'] | 1), PCG_MAGIC_MODULUS_1)
    xorshifted = wrap(((oldstate >> 18) ^ oldstate) >> 27, PCG_MAGIC_MODULUS_2)
    rot = wrap(oldstate >> 59, PCG_MAGIC_MODULUS_2)
    return wrap((xorshifted >> rot) | (xorshifted << (-rot & 31)), PCG_MAGIC_MODULUS_2)

rng = {
    'state': 0,
    'inc': wrap(key['rng_init_seq'] << 1 | 1, PCG_MAGIC_MODULUS_1)
}
rng_next(rng)
rng['state'] = wrap(rng['state'] + key['rng_init_state'], PCG_MAGIC_MODULUS_1)
rng_next(rng)

# Order and parse the partitions based on the RNG
next_idx = 0
while next_idx < len(partitions):
    order_prefix = rng_next(rng)
    formatted_order_prefix = f"{order_prefix:08x}"
    for i in range(next_idx, len(partitions)):
        if partitions[i].startswith(formatted_order_prefix):
            data = partitions[i][len(formatted_order_prefix):][key['noise_len']:]
            partitions[i], partitions[next_idx] = partitions[next_idx], partitions[i]
            partitions[next_idx] = data
            next_idx += 1

# Reconstruct the hex string from partitions and handle padding, then decode the base64 to retrieve the original string
print(base64.urlsafe_b64decode(bytes.fromhex(''.join(partitions)[:-1] if len(''.join(partitions)) % 2 != 0 else ''.join(partitions))[:key['base64_len']]).decode('utf-8'))
