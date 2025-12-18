#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <argon2.h>
#include <openssl/sha.h>
#include <sys/mman.h>

int main() {
	printf("slpg utility\n");
	
	// Get salt
	char* salt = NULL;
	size_t dummy; // Size not needed
	printf("enter salt: ");
	ssize_t saltlen = getline(&salt, &dummy, stdin);
	if (saltlen == -1) {
		printf("getline failed\n");
		return -1;
	}
	if (saltlen > 0 && salt[saltlen-1] == '\n') salt[--saltlen] = '\0';

	// SHA-256-encode salt
	uint8_t hashedsalt[32];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, salt, saltlen);
	SHA256_Final(hashedsalt, &sha256);

	// Get master password
	char* master = getpass("enter master: ");
	ssize_t masterlen = strlen(master);
	mlock(master, masterlen);

	// Calculate hash
	uint8_t hash[32];
	int result = argon2id_hash_raw(
			4, // Iterations
			262144, // KiB
			2, // Parallelism
			master,
			masterlen,
			hashedsalt,
			32,
			hash, // Buffer
			32 // Bytes of hash
	);
	if (result != ARGON2_OK) {
		printf("argon2 encoding error: %i (0x%x)\n", result, result);
		return -1;
	}
	mlock(hash, 32);

	// Format output
	printf("\nhash output:\n");
	for (int i=0; i<32; i++) {
		if (i == 0) printf("!1");
		else if (i == 1) printf("Aa");
		else {
			uint8_t b = hash[i];
			uint8_t l = b & 15;
			uint8_t h = b >> 4;
			printf("%x%x", l, h);
		}
	}
	printf("\n");

	// Zero-out buffers
	void* (*volatile scrub)(void*, int, size_t) = memset;
	scrub(master, 0, masterlen);
	scrub(hash, 0, 32);
	munlock(master, masterlen);
	munlock(hash, 32);

	// Success
	return 0;
}
