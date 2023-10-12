#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

struct PasswordManager {
    char *password;
    unsigned short invalidTries;
    unsigned short maximumTries;
    bool loggedIn;
};

struct PasswordManager newPasswordManagerWithMaxTries(int maxTries) {
    struct PasswordManager newPM = { 
        .password = "supersecret", 
        .invalidTries = 0,
        .maximumTries = maxTries,
        .loggedIn = false
    };

    return newPM;
}

void tryLogin(struct PasswordManager *pm, char *tryedPassword) {
    if (pm->invalidTries < pm->maximumTries) {
        if (!strcmp(pm->password, tryedPassword)) {
            pm->loggedIn = true;
            pm->invalidTries = 0;
        } else {
            pm->loggedIn = false;
            pm->invalidTries++;
        }
    } else {
        puts("No more password tries allowed");
    }
}

__AFL_FUZZ_INIT();

int main(void) {

    __AFL_INIT();

    unsigned char *Data = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT
    int Size = __AFL_FUZZ_TESTCASE_LEN;  // don't use the macro directly in a
                                          // call!

    uint32_t public_len = *(unsigned int *)Data;
    uint32_t secret_len = Size - public_len - sizeof(public_len);
    const uint8_t *public_in = Data + sizeof(public_len);
    const uint8_t *secret_in = public_in + public_len;

    unsigned short passwordAttempts = 0;
    int bytes = secret_len < sizeof(passwordAttempts) ? 
                    secret_len : 
                    sizeof(passwordAttempts);

    for (int i = 0; i < bytes; i++) {
        passwordAttempts |= secret_in[i] << 8 * i;
    }

    const char *exitKeyword = "exit";
    bool exit = false;

    struct PasswordManager pm = newPasswordManagerWithMaxTries(passwordAttempts);

    printf("To exit, type: %s\n", exitKeyword);

    char *str = malloc(public_len + 1);
    memcpy(str, public_in, public_len);
    str[public_len] = 0; // terminate the string

    char *input, *temp;
    input = strtok_r(str, "\n", &temp);
    while (input && !exit) {
        printf("Enter password:\n");

        exit |= strcmp(input, exitKeyword) == 0;
        tryLogin(&pm, input);
        input = strtok_r(NULL, "\n", &temp);
    }

    printf("Run completed, run again\n");

    return 0;
}