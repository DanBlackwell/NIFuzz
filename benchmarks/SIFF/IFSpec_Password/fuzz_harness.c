#include "password.c"

__AFL_FUZZ_INIT();

int main(void) {

    __AFL_INIT();

    unsigned short passwordAttempts = 0;
    int bytes = EXPLICIT_SECRET_LEN < sizeof(passwordAttempts) ? 
                    EXPLICIT_SECRET_LEN : 
                    sizeof(passwordAttempts);

    for (int i = 0; i < bytes; i++) {
        passwordAttempts |= EXPLICIT_SECRET_IN[i] << 8 * i;
    }

    const char *exitKeyword = "exit";
    bool exit = false;

    struct PasswordManager pm = PasswordManager_newWithMaxTries(passwordAttempts);

    printf("To exit, type: %s\n", exitKeyword);

    char *str = malloc(EXPLICIT_PUBLIC_LEN + 1);
    memcpy(str, EXPLICIT_PUBLIC_IN, EXPLICIT_PUBLIC_LEN);
    str[EXPLICIT_PUBLIC_LEN] = 0; // terminate the string

    char *input, *temp;
    input = strtok_r(str, "\n", &temp);
    while (input && !exit) {
        printf("Enter password:\n");

        exit |= strcmp(input, exitKeyword) == 0;
        char *res = PasswordManager_tryLogin(&pm, input);
	    if (res) puts(res);
        input = strtok_r(NULL, "\n", &temp);
    }

    printf("Run completed, run again\n");

    return 0;
}
