// simple test program for pe binary testing
#include <stdio.h>

int global_data = 42;
const char* message = "hello from pe";

int add(int a, int b) {
    return a + b;
}

int main(void) {
    int result = add(10, 20);
    printf("%s: %d\n", message, result);
    return 0;
}
