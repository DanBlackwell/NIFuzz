#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

char *outputBuf;
int outputBufSize;
int outputBufLen;

typedef unsigned int dollars;

typedef struct Account {
    dollars balance;
    void (*logTransaction)(struct Account *, bool);
    void (*logError)(char *);
} Account;

void logError(char *message) {
    int msglen = strlen(message);
    if (outputBufLen + msglen >= outputBufSize) {
        if (outputBufSize == 0) outputBufSize = 64;
        while (outputBufSize <= outputBufLen + msglen) outputBufSize *= 2;
        outputBuf = realloc(outputBuf, outputBufSize);
    }

    strcpy(outputBuf + outputBufLen, message);
    outputBufLen += msglen;
}

void logTransaction(Account *account, bool isDeposit) {
    // char *transaction = isDeposit ? "Deposit" : "Withdrawal";
    // printf("%s completed, new balance: %lf\n", transaction, account->balance);
}

Account newAccount() {
    Account newAccount = {
        .balance = 0,
        .logError = logError,
        .logTransaction = logTransaction,
    };
    return newAccount;
}

void deposit(Account *account, dollars amount) {
    if (amount > 0) {
        account->balance += amount;
        account->logTransaction(account, true);
    } else {
        account->logError("Cannot deposit a non-positive amount");
    }
}

bool withdraw(Account *account, dollars amount) {
    if (amount > 0) {
        dollars newAmount = account->balance - amount;
        if (newAmount > 0) {
            account->balance = newAmount;
            account->logTransaction(account, false);
            return true;
        } else {
            char string[256];
            int res = snprintf(string, sizeof(string), 
                "Account has insufficient funds to withdraw %ld", amount);
            if (res > sizeof(string)) exit(1);

            account->logError(string);
            return false;
        }
    }
    account->logError("Cannot withdraw a non-positive amount");
    return false;
}

///////////////////////////////////////////////////////////////////////////////

typedef struct Beneficiary {
    double received;
} Beneficiary;

void receive(Beneficiary *b, dollars amount) {
    b->received += amount;
}

///////////////////////////////////////////////////////////////////////////////

typedef struct AccountOwner {
    Account *account;
    void (*payBeneficiary)(struct AccountOwner *, Beneficiary *, dollars);
} AccountOwner;

void payBeneficiary(AccountOwner *owner, Beneficiary *b, dollars amount) {
    bool transactionPossible = withdraw(owner->account, amount);
    if (transactionPossible) {
        receive(b, amount);
    }
}

AccountOwner newAccountOwner(Account *account) {
    AccountOwner newAccountOwner = { 
        .account = account, 
        .payBeneficiary = payBeneficiary 
    };
    return newAccountOwner;
}

///////////////////////////////////////////////////////////////////////////////

#define INIT_INPUT(num) dollars transfer ## num;
#define GENERATE_OUTPUT(num) char *output ## num = test(depositAmount, transfer ## num);
#define OUTPUTS_EQUAL(num1, num2) !strcmp(output ## num1, output ## num2)

#include "distinctions.h"

char *test(dollars depositAmount, dollars transferAmount) {
    Account account = newAccount();
    deposit(&account, depositAmount);
    AccountOwner owner = newAccountOwner(&account);
    Beneficiary beneficiary = { .received = 0 };
    owner.payBeneficiary(&owner, &beneficiary, transferAmount);

    char *output = malloc(outputBufLen + 1); 
    if (!outputBufLen) {
        output[0] = 0;
	return output;
    }

    strcpy(output, outputBuf);
    *outputBuf = 0;
    outputBufLen = 0;

    return output;
}

int main(void) {
    dollars depositAmount;
    
    CHECK_LEAKAGE()
 
    return 0;
}
