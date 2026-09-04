/* Minimal on-device ABI smoke test for the token-per-prctl contract. */
#include <green/abi.h>
#include <errno.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(void)
{
    struct green_shadow_rpc rpc = {0};
    unsigned long token = 0x475245454e544553UL ^ (unsigned long)getpid();
    unsigned long wrong = token ^ 0x9e3779b97f4a7c15UL;
    long ret;

    ret = prctl((int)PR_GREEN_SHADOW_TOKEN_REGISTER, (unsigned long)getpid(),
                token, 0, 0);
    if (ret < 0) {
        perror("token register (is green.kpm loaded?)");
        return 1;
    }
    rpc.version = GREEN_SHADOW_ABI_VERSION;
    rpc.op = GREEN_SHADOW_OP_COUNT;
    rpc.pid = 0;
    ret = prctl((int)PR_GREEN_SHADOW_REQUEST, wrong,
                (unsigned long)&rpc, 0, 0);
    if (ret >= 0) {
        fprintf(stderr, "invalid token was accepted\n");
        return 1;
    }
    printf("invalid token rejected: %ld\n", ret);
    ret = prctl((int)PR_GREEN_SHADOW_REQUEST, token,
                (unsigned long)&rpc, 0, 0);
    printf("authenticated count: %ld\n", ret);
    if (ret < 0) {
        errno = (int)-ret;
        perror("shadow request");
        return 1;
    }
    ret = prctl((int)PR_GREEN_SHADOW_TOKEN_REVOKE, (unsigned long)getpid(),
                token, 0, 0);
    if (ret < 0) {
        perror("token revoke");
        return 1;
    }
    ret = prctl((int)PR_GREEN_SHADOW_REQUEST, token,
                (unsigned long)&rpc, 0, 0);
    if (ret >= 0) {
        fprintf(stderr, "revoked token was accepted\n");
        return 1;
    }
    printf("revoked token rejected: %ld\n", ret);
    return 0;
}
