#include "password.c"

char *test(unsigned short passwordAttempts, char *str) {
    size_t outputSize = 128;
    char *output = malloc(outputSize);
    int outputLen = 0;

#define STORE_TO_OUTPUT(...) { \
    int len = snprintf(output + outputLen, outputSize - outputLen, \
                       __VA_ARGS__); \
    if (outputLen + len + 1 >= outputSize) { \
        while (outputLen + len + 1 >= outputSize) outputSize *= 2; \
        output = realloc(output, outputSize); \
        if (!output) exit(1); \
        len = snprintf(output + outputLen, outputSize - outputLen, \
                       __VA_ARGS__); \
    } \
    outputLen += len; \
}

    const char *exitKeyword = "exit";
    bool shouldExit = false;

    struct PasswordManager pm = PasswordManager_newWithMaxTries(passwordAttempts);

    STORE_TO_OUTPUT("To exit, type: %s\n", exitKeyword);

    char *input, *temp;
    input = strtok_r(str, "\n", &temp);
    while (input && !shouldExit) {
        STORE_TO_OUTPUT("Enter password:\n");

        shouldExit |= strcmp(input, exitKeyword) == 0;
        char *res = PasswordManager_tryLogin(&pm, input);
        if (res) { STORE_TO_OUTPUT("%s", res); }
        input = strtok_r(NULL, "\n", &temp);
    }

    STORE_TO_OUTPUT("Run completed, run again\n");
}

#define CHECK_DISTINCTIONS(low, hi) \
char input ## low[20]; input ## low[19] = 0; \
assert(!strcmp(test(passwordAttempts, input ## hi), test(passwordAttempts, input ## low)));

#define CHECK_DISTINCTIONS_INIT(hi) char input ## hi[20]; input ## hi[19] = 0;

#include "distinctions.h"

int main(void) {
    unsigned short passwordAttempts;

    { CHECK_1_BITS_LEAKAGE() }

    { CHECK_8_BITS_LEAKAGE() }
    return 0;
}
