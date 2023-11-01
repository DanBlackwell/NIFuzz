#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

char outputBuf[4096];
int outputBufLen;

typedef struct Review {
    int reviewer_id;
    int score;
    char *content;
} Review;

int compareReviews(const void *rp1, const void *rp2) {
    const Review *lhs = rp1, *rhs = rp2;

    if (lhs->reviewer_id != rhs->reviewer_id) {
        return lhs->reviewer_id < rhs->reviewer_id;
    } else if (lhs->score != rhs->score) {
        return lhs->score < rhs->score;
    } else {
        return strcmp(lhs->content, rhs->content);
    }
}

typedef struct ReviewProcess {
    Review *reviews;
    size_t len;
    size_t allocated;
} ReviewProcess;

void ReviewProcess_addReview(ReviewProcess *rp, int reviewer_id, int score, char *content) {
    Review r = {
        .reviewer_id = reviewer_id,
        .score = score,
        .content = content
    };

    if (rp->len + 1 > rp->allocated) {
        rp->allocated *= 2;
        rp->reviews = realloc(rp->reviews, sizeof(rp->reviews[0]) * rp->allocated);
    }

    rp->reviews[rp->len] = r;
    rp->len++;
}

void ReviewProcess_sendNotifications(ReviewProcess *rp) {
    qsort(rp->reviews, rp->len, sizeof(rp->reviews[0]), compareReviews);

    for (int i = 0; i < rp->len; i++) {
        Review *r = &rp->reviews[i];
        int written = snprintf(outputBuf + outputBufLen, sizeof(outputBuf) - outputBufLen,
                               "---\n"
                               "Score: %d\n"
                               "Review: %s\n"
                               "---\n", r->score, r->content);
        assert(outputBufLen + written <= sizeof(outputBuf));
        outputBufLen += written;
    }
}

///////////////////////////////////////////////////////////////////////////////

#include "distinctions.h"

#define INIT_INPUT(num)
#define GENERATE_OUTPUT(num) char *output ## num = test(&rp);
#define OUTPUTS_EQUAL(num1, num2) !strcmp(output ## num1, output ## num2)

char *test(ReviewProcess *rp) {
    for (int i = 0; i < rp->len; i++) {
        int reviewerID;

        while (true) {
            checkClashes:
            for (int i = 0; i < rp->len; i++) {
                if (rp->reviews[i].reviewer_id == reviewerID) {
                    reviewerID++; 
                    goto checkClashes;
                }
            }
            break;
        }
        rp->reviews[i].reviewer_id = reviewerID;
    }

    ReviewProcess_sendNotifications(rp);
    char *output = malloc(outputBufLen + 1);
    strcpy(output, outputBuf);
    *outputBuf = 0;
    outputBufLen = 0;

    return output;
}

int main(void) {
    ReviewProcess rp = { 
        .allocated = 2,
        .reviews = malloc(2 * sizeof(Review)),
        .len = 0 
    };

    int numReviewers;
    numReviewers = numReviewers % 8 + 2;

    for (int i = 0; i < numReviewers; i++) {
        int reviewScore;
        reviewScore = reviewScore % 4 + 1;

        int reviewLen;
        reviewLen = reviewLen % 5 + 1;
        char *reviewComment = malloc(reviewLen);
        reviewComment[reviewLen - 1] = 0;

        ReviewProcess_addReview(&rp, 0, reviewScore, reviewComment);
    }

    CHECK_LEAKAGE()

    return 0;
}
