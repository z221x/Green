/* Minimal resident victim process for agent self-testing. */
#include <stdio.h>
#include <unistd.h>
__attribute__((noinline)) int hookme_victim(int x)
{
    asm volatile("" ::: "memory");
    return x + 1;
}
int main(void)
{
    int i = 0;
    for (;;) {
        printf("hookme alive %d victim=%d\n", i++, hookme_victim(1));
        fflush(stdout);
        sleep(1);
    }
}
