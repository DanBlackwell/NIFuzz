#include <iostream>
#include <string>
#include <cstdio>

extern "C" {
  #include <unistd.h>
  #include <stdint.h>
  #include <stdlib.h>
  #include <string.h>
  #include <assert.h>
  #include <sys/time.h>

  __AFL_FUZZ_INIT();
}

class ErrorLog {
public:
    void logError(std::string message) {
        std::cerr << message << std::endl;
    }
};

class TransactionLog {
public:
    void logTransaction(std::string message) {
        // std::cout << message << std::endl;
    }
};

class Account {
public:
    double balance;
    ErrorLog errorLog;
    TransactionLog transactionLog;

    void deposit(double amount) {
        if (amount > 0) {
            balance += amount;
            logTransaction(true);
        } else {
            logError("Cannot deposit a non-positive amount.");
        }
    }

    bool withdraw(double amount) {
        if (amount > 0) {
            double newAmount = balance - amount;
            if (newAmount > 0) {
                balance = newAmount;
                logTransaction(false);
                return true;
            } else {
                char buf[2048];
                sprintf(buf, "Account has insufficient funds to withdraw %.2f", amount);
                logError(buf);
                return false;
            }
        }
        logError("Cannot withdraw a non-positive amount.");
        return false;
    }

    void logError(std::string message) {
        errorLog.logError(message);
    }

private:
    void logTransaction(bool isDeposit) {
        std::string transaction = isDeposit ? "Deposit" : "Withdrawal";
        char buf[2048];
        sprintf(buf, "%s completed, new balance: %.2f", transaction.c_str(), balance);
        transactionLog.logTransaction(buf);
    }

};

class Beneficiary {
public:
    double received;

    void receive(double amount) {
        received += amount;
    }
};

class AccountOwner {
private:
    Account account;

public:
    AccountOwner(Account account) {
        this->account = account;
    }

    void payBeneficiary(Beneficiary b, double amount) {
        bool transactionPossible = account.withdraw(amount);
        if (transactionPossible) {
            b.receive(amount);
        }
    }
};

union converter {
  char bytes[sizeof(float)];
  float floatVal;
} converter;

int main(int argc, char **argv) {
    // Start the forkserver at this point (i.e., forks will happen here)
    __AFL_INIT();
    fflush(stdout);
    fflush(stderr);

    // The following line is also needed for shared memory testcase fuzzing
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT
    unsigned int len = __AFL_FUZZ_TESTCASE_LEN;

    unsigned int public_len = *(unsigned int *)buf;
    unsigned int secret_len = len - public_len - sizeof(public_len);
    unsigned char *public_buf = buf + sizeof(public_len);
    unsigned char *secret_buf = public_buf + public_len;

    converter.floatVal = 0.0;
    for (int i = 0; i < (secret_len < sizeof(converter.floatVal) ? secret_len : sizeof(converter.floatVal)); i++) {
        converter.bytes[i] = secret_buf[i];
    }
    double deposit = converter.floatVal;
    deposit = (deposit != deposit || deposit < 0.01) ? 0.01 : deposit;

    converter.floatVal = 0.0;
    // memset(converter.bytes, 0, sizeof(converter.bytes));
    for (int i = 0; i < (public_len < sizeof(converter.floatVal) ? public_len : sizeof(converter.floatVal)); i++) {
        converter.bytes[i] = public_buf[i];
    }
    double transfer = converter.floatVal;

    Account account = Account();
    account.deposit(deposit);
    AccountOwner owner = AccountOwner(account);
    Beneficiary beneficiary = Beneficiary();
    owner.payBeneficiary(beneficiary, transfer);
    // timeval t1;
    // gettimeofday(&t1, NULL);
    // printf("%d\n", t1.tv_usec);

    return 0;
}