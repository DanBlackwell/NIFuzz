#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

__AFL_FUZZ_INIT();

typedef unsigned short dollars;

typedef struct Account {
    dollars balance;
    void (*logTransaction)(struct Account *, bool);
    void (*logError)(char *);
} Account;

void logError(char *message) {
    fprintf(stderr, "%s\n", message);
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
                "Account has insufficient funds to withdraw %hu", amount);
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

int main(void) {

    __AFL_INIT();

    dollars depositAmount = 0;
    for (int i = 0; i < (EXPLICIT_SECRET_LEN < sizeof(dollars) ? EXPLICIT_SECRET_LEN : sizeof(dollars)); i++) {
        depositAmount |= EXPLICIT_SECRET_IN[i] << 8 * i;
    }
    if (depositAmount < 0) { depositAmount = -depositAmount; }
    if (depositAmount == 0) { depositAmount = 1; }

    dollars transferAmount = 0;
    for (int i = 0; i < (EXPLICIT_PUBLIC_LEN < sizeof(dollars) ? EXPLICIT_PUBLIC_LEN : sizeof(dollars)); i++) {
        transferAmount |= EXPLICIT_PUBLIC_IN[i] << 8 * i;
    }
    if (transferAmount < 0) { transferAmount = -transferAmount; }

    Account account = newAccount();
    deposit(&account, depositAmount);
    AccountOwner owner = newAccountOwner(&account);
    Beneficiary beneficiary = { .received = 0 };
    owner.payBeneficiary(&owner, &beneficiary, transferAmount);

    return 0;
}
