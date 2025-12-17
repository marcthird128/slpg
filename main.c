#include <stdio.h>
#include <stdlib.h>
#include <argon2.h>

int main() {
	printf("slpg utility\n");
	
	char* salt = NULL;
	char* master = NULL;

	size_t dummy; // Size not needed
	
	// Get salt
	printf("enter salt: ");
	ssize_t saltlen = getline(&salt, &dummy, stdin);
	if (saltlen == -1) {
		printf("getline failed\n");
		return -1;
	}
	if (salt[saltlen-1] == '\n') salt[saltlen-1] = '\0';

	// Get master password
	printf("enter master: ");
	ssize_t masterlen = getline(&master, &dummy, stdin);
	if (masterlen == -1) {
		printf("getline failed\n");
		return -1;
	}
	if (master[masterlen-1] == '\n') master[masterlen-1] = '\0';

	// Calculate hash
	char hash[1000000];
	int result = argon2id_hash_encoded(
			4, // Iterations
			262144, // KiB
			2, // Parallelism
			master,
			masterlen,
			salt,
			saltlen,
			32, // Bytes of hash
			hash,
			sizeof(hash)
	);

	printf("Output: %s\n", hash);
	
	return 0;
}
