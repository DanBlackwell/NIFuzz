#include "password.c"
#include "generate_random.h"

int main(void) {
    unsigned short passwordAttempts;

    const char *exitKeyword = "exit";
    bool exit = false;

    for (int i = 0; i < SAMPLES / REPS; i++) {
        FILL_RAND_VAR(passwordAttempts);
        struct PasswordManager pm = PasswordManager_newWithMaxTries(passwordAttempts);

        for (int r = 0; r < REPS; r++) {
            printf("(%hu,", passwordAttempts);
            printf("To exit; type: %s_", exitKeyword);

            char str[120];
            FILL_RAND_BUF(str);
            str[119] = 0; // terminate the string

            char *input, *temp;
            input = strtok_r(str, "\n", &temp);
            while (input && !exit) {
                printf("Enter password:_");

                exit |= strcmp(input, exitKeyword) == 0;
                char *res = PasswordManager_tryLogin(&pm, input);

                if (res) {
                    char *tmp = malloc(strlen(res) + 1);
                    int pos = 0;
                    do {
                        if (res[pos] == '\n') tmp[pos] = '_';
                        else if (res[pos] == ',') tmp[pos] = ';';
                        else tmp[pos] = res[pos];
                    } while(res[pos++]);

                    printf("%s", tmp);
                    free(tmp);
                }

                input = strtok_r(NULL, "\n", &temp);
            }

            printf("Run completed; run again)\n");
        }
    }

    return 0;
}
