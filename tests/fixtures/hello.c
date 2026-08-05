/*
 * The Mach-O fixture every integration test signs.
 *
 * Kept as source rather than a checked-in binary so it builds for whatever
 * architecture the tests run on. `support::fixture::pristine_hello` compiles it
 * once per test run; tests assert on the output below to prove that signing
 * left a working executable behind.
 */

#include <stdio.h>

int main(void) {
    puts("hello, signers");
    return 0;
}
