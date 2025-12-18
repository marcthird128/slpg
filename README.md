# StateLess Password Generator

Uses Argon2 to create password hashes.

## Parameters

 * Hash Function: argon2id version 13
 * Iterations: 4
 * Memory: 256 MiB (262144 KiB)
 * Parallelism: 2
 * Hash bytes: 32

## Algorithm

There are two inputs:

 1. Salt. This is the name (e.g. domain name) of the service
    which the password is generated for.
 2. Master. This is the master password that must be very strong
    and the same every time.

The algorithm is as follows:

 1. Use SHA-256 to hash the salt. Store the resulting raw bytes
    in a 32-byte buffer. Call this the `hashed salt`.
 2. Use the hashing function and the parameters in the [Parameters](#parameters)
    section with the `hashed salt` as salt and the master password
    as the main input to generate a 32-byte buffer. Call this the `hash`.
 3. Treat the `hash` as a big-endian 256-bit number, convert to standard 
    hexadecimal, pad with zeros to make it 64 characters long, reverse the
    string, and then output it.

## Security

This is a very secure algorithm.

## Implementation

Included is a reference implementation written in C. To compile it, run

```
./build.sh
```

The output will be the executable `slpg`. Run it with no arguments. It will
prompt you for the salt text and the master password, and will output in
the correct format.

## Verification

Here is example input to verify your slpg executable:

Salt: `hello`
Master: `world`
Output: `62d6c38b8ac33848df367188634107373dae0809a54957af42baa248700fb774`

