#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <argon2.h>
#include <openssl/sha.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {
	int tty = isatty(fileno(stdin)); // Be quiet for scripts
	if (tty) printf("slpg utility\n");

	char *salt, *master; // Buffers
	
	size_t dummy, len; // Reused
	
	// Get salt
	salt = NULL; dummy = 0;
	if (tty) printf("enter salt: ");
	len = getline(&salt, &dummy, stdin);
	if (len == -1) {
		if (tty) printf("getline failed\n");
		return -1;
	}
	if (len > 0 && salt[len-1] == '\n') salt[--len] = '\0';

	// SHA-256-encode salt
	uint8_t hashedsalt[32];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, salt, len);
	SHA256_Final(hashedsalt, &sha256);

	// Free salt
	free(salt);
	salt = NULL;

	// Get master password
	if (tty) {
		master = getpass("enter master: ");
		len = strlen(master);
		char* buf = malloc(len + 1);
		if (buf == NULL) {
			if (tty) printf("malloc failed\n");
			return -2;
		}
		strcpy(buf, master);
		master = buf;
	} else {
		master = NULL; dummy = 0;
		len = getline(&master, &dummy, stdin);
		if (len == -1) {
			if (tty) printf("getline failed\n");
			return -3;
		}
		if (len > 0 && master[len-1] == '\n') master[--len] = '\0';
	}
	mlock(master, len);

	// Calculate hash
	uint8_t hash[32];
	int result = argon2id_hash_raw(
			4, // Iterations
			262144, // KiB
			2, // Parallelism
			master,
			len,
			hashedsalt,
			32,
			hash, // Buffer
			32 // Bytes of hash
	);
	if (result != ARGON2_OK) {
		if (tty) printf("argon2 encoding error: %i (0x%x)\n", result, result);
		return -4;
	}
	mlock(hash, 32);

	// Format output
	if (tty) printf("\nhash output:\n");
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
	if (tty) printf("\n");

	// Zero-out buffers
	void* (*volatile scrub)(void*, int, size_t) = memset;
	scrub(master, 0, len);
	scrub(hash, 0, 32);
	munlock(master, len);
	free(master);
	munlock(hash, 32);

	// Success
	return 0;
}
