#include "password.c"

char *test(unsigned short passwordAttempts, char *str) {
    int outputSize = 128;
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

    return output;
}

#define INIT_INPUT(num) char input ## num[20]; input ## num[19] = 0;
#define GENERATE_OUTPUT(num) char *output ## num = test(passwordAttempts, input ## num);
#define OUTPUTS_EQUAL(num1, num2) !strcmp(output ## num1, output ## num2)

#include "distinctions.h"

int main(void) {
    unsigned short passwordAttempts;


    CHECK_LEAKAGE()
    return 0;
}
