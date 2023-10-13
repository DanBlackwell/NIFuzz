#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

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
        printf("---\n"
               "Score: %d\n"
               "Review: %s\n"
               "---\n", r->score, r->content);
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

    ReviewProcess rp = { 
        .allocated = 2,
        .reviews = malloc(2 * sizeof(Review)),
        .len = 0 
    };

    int secretPos = 0, publicPos = 0;
    int numReviewers = public_in[0] % 8 + 2;

    for (int i = 0; i < numReviewers && publicPos < public_len; i++) {
        int reviewerID = 0;
        int secLen = secret_len - secretPos;
        if (secLen == 0) {
            reviewerID = i;
        } else {
            int len = secLen < sizeof(reviewerID) ? secLen : sizeof(reviewerID);

            for (int j = secretPos; j < secretPos + len; j++) {
                reviewerID |= secret_in[j] << 8 * (j - secretPos);
            }

            while (true) {
                checkClashes:
                for (int i = 0; i < rp.len; i++) {
                    if (rp.reviews[i].reviewer_id == reviewerID) {
                        reviewerID++; 
                        goto checkClashes;
                    }
                }
                break;
            }

            secretPos += len;
        }

        int reviewScore = 1;
        if (publicPos < public_len) {
            reviewScore = public_in[publicPos++] % 4 + 1;
        }

        int reviewLen = 0;
        if (public_len - publicPos > 5) {
            // 5-31 characers per review
            reviewLen = public_in[publicPos] % (public_len - publicPos - 5) + 5;
            publicPos++;
        } else {
            // Don't try forming a review with comment <5 chars long
            break;
        }

        char *reviewComment = malloc(reviewLen);
        char *tmp = reviewComment;
        for (int i = 0; i < reviewLen; i++) {
            *tmp = public_in[publicPos++];
            // Overwrite any \0's so the string doesn't terminate early
            if (*tmp) tmp++;
        }
        *tmp = 0;

        ReviewProcess_addReview(&rp, reviewerID, reviewScore, reviewComment);
    }

    ReviewProcess_sendNotifications(&rp);

    return 0;
}