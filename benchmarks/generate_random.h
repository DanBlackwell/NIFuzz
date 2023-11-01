#define FILL_RAND(var) { \
		int rand_buf[sizeof(var) / sizeof(int) + (sizeof(var) % sizeof(int) == 0 ? 0 : 1)]; \
		for (int i = 0; i < sizeof(rand_buf) / sizeof(rand_buf[0]); i++) rand_buf[i] = rand(); \
		memcpy(&var, rand_buf, sizeof(var)); \
	}
