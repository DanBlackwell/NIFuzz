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

struct PasswordManager PasswordManager_newWithMaxTries(int maxTries) {
    struct PasswordManager newPM = { 
        .password = "supersecret", 
        .invalidTries = 0,
        .maximumTries = maxTries,
        .loggedIn = false
    };

    return newPM;
}

char *PasswordManager_tryLogin(struct PasswordManager *pm, char *tryedPassword) {
    if (pm->invalidTries < pm->maximumTries) {
        if (!strcmp(pm->password, tryedPassword)) {
            pm->loggedIn = true;
            pm->invalidTries = 0;
        } else {
            pm->loggedIn = false;
            pm->invalidTries++;
        }
	return NULL;

    } else {
        return "No more password tries allowed\n";
    }
}
