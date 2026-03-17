/*
 * test_decompiler.c
 *
 * comprehensive test binary for sedec decompiler validation.
 * covers: arithmetic, control flow, loops, recursion, pointers,
 * structs, switch tables, function calls, and memory operations.
 *
 * compile:
 *   gcc -O0 -g -o test_decompiler test_decompiler.c
 *   gcc -O2 -o test_decompiler_opt test_decompiler.c
 *
 * then run sedec against both to compare output quality.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* 1. simple arithmetic - tests basic ir lifting and constant folding  */
/* ------------------------------------------------------------------ */

int add(int a, int b) {
    return a + b;
}

int sub(int a, int b) {
    return a - b;
}

int mul(int a, int b) {
    return a * b;
}

/* integer division - tests magic divisor idiom recovery at -O2 */
int div_by_7(int n) {
    return n / 7;
}

int mod_by_3(int n) {
    return n % 3;
}

/* ------------------------------------------------------------------ */
/* 2. bitwise ops - tests flag elimination and shift idioms            */
/* ------------------------------------------------------------------ */

uint32_t bit_and(uint32_t a, uint32_t b) { return a & b; }
uint32_t bit_or(uint32_t a, uint32_t b)  { return a | b; }
uint32_t bit_xor(uint32_t a, uint32_t b) { return a ^ b; }
uint32_t bit_not(uint32_t a)             { return ~a; }
uint32_t shl(uint32_t a, int n)          { return a << n; }
uint32_t shr(uint32_t a, int n)          { return a >> n; }

/* strength reduction target: multiply by power of 2 */
uint32_t mul_by_16(uint32_t x) {
    return x * 16;
}

/* ------------------------------------------------------------------ */
/* 3. control flow - tests cfg recovery and structuring                */
/* ------------------------------------------------------------------ */

/* simple if-else */
int max(int a, int b) {
    if (a > b)
        return a;
    return b;
}

/* nested if-else chain */
const char *classify_int(int n) {
    if (n < 0)
        return "negative";
    else if (n == 0)
        return "zero";
    else if (n < 10)
        return "small";
    else if (n < 100)
        return "medium";
    else
        return "large";
}

/* ternary - tests phi node reconstruction */
int abs_val(int x) {
    return x < 0 ? -x : x;
}

/* ------------------------------------------------------------------ */
/* 4. switch statement - tests jump table recovery                     */
/* ------------------------------------------------------------------ */

const char *day_name(int d) {
    switch (d) {
        case 0: return "sunday";
        case 1: return "monday";
        case 2: return "tuesday";
        case 3: return "wednesday";
        case 4: return "thursday";
        case 5: return "friday";
        case 6: return "saturday";
        default: return "unknown";
    }
}

/* sparse switch - tests if-chain vs jump table heuristic */
int sparse_switch(int x) {
    switch (x) {
        case 1:   return 10;
        case 10:  return 20;
        case 100: return 30;
        case 999: return 40;
        default:  return -1;
    }
}

/* ------------------------------------------------------------------ */
/* 5. loops - tests loop recovery (while/for/do-while)                 */
/* ------------------------------------------------------------------ */

/* counted for loop */
int sum_range(int n) {
    int s = 0;
    for (int i = 0; i < n; i++)
        s += i;
    return s;
}

/* while loop with early exit */
int find_first_zero(const uint8_t *buf, int len) {
    int i = 0;
    while (i < len) {
        if (buf[i] == 0)
            return i;
        i++;
    }
    return -1;
}

/* do-while */
uint32_t count_bits(uint32_t x) {
    uint32_t count = 0;
    do {
        count += x & 1;
        x >>= 1;
    } while (x != 0);
    return count;
}

/* nested loops - tests loop nesting depth recovery */
int matrix_trace(int m[4][4]) {
    int trace = 0;
    for (int i = 0; i < 4; i++)
        trace += m[i][i];
    return trace;
}

/* ------------------------------------------------------------------ */
/* 6. recursion - tests call graph and stack frame analysis            */
/* ------------------------------------------------------------------ */

/* classic fibonacci - tests recursive call pattern */
int fib(int n) {
    if (n <= 1)
        return n;
    return fib(n - 1) + fib(n - 2);
}

/* tail-recursive factorial - tests tail call optimization detection */
static int fact_tail(int n, int acc) {
    if (n <= 1)
        return acc;
    return fact_tail(n - 1, n * acc);
}

int factorial(int n) {
    return fact_tail(n, 1);
}

/* mutual recursion - tests interprocedural analysis */
static int is_even(int n);
static int is_odd(int n);

static int is_even(int n) {
    if (n == 0) return 1;
    return is_odd(n - 1);
}

static int is_odd(int n) {
    if (n == 0) return 0;
    return is_even(n - 1);
}

/* ------------------------------------------------------------------ */
/* 7. pointers and memory - tests vsa and alias analysis               */
/* ------------------------------------------------------------------ */

void swap(int *a, int *b) {
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

/* pointer arithmetic */
int dot_product(const int *a, const int *b, int n) {
    int result = 0;
    for (int i = 0; i < n; i++)
        result += a[i] * b[i];
    return result;
}

/* memcpy idiom - tests memcpy/memset pattern recognition */
void copy_bytes(uint8_t *dst, const uint8_t *src, int n) {
    for (int i = 0; i < n; i++)
        dst[i] = src[i];
}

/* memset idiom */
void zero_bytes(uint8_t *buf, int n) {
    for (int i = 0; i < n; i++)
        buf[i] = 0;
}

/* ------------------------------------------------------------------ */
/* 8. structs - tests struct layout and field access recovery          */
/* ------------------------------------------------------------------ */

typedef struct {
    int x;
    int y;
    int z;
} vec3_t;

typedef struct {
    char name[32];
    int  age;
    float score;
} record_t;

vec3_t vec3_add(vec3_t a, vec3_t b) {
    vec3_t r;
    r.x = a.x + b.x;
    r.y = a.y + b.y;
    r.z = a.z + b.z;
    return r;
}

int vec3_dot(vec3_t a, vec3_t b) {
    return a.x * b.x + a.y * b.y + a.z * b.z;
}

void record_init(record_t *r, const char *name, int age, float score) {
    strncpy(r->name, name, sizeof(r->name) - 1);
    r->name[sizeof(r->name) - 1] = '\0';
    r->age   = age;
    r->score = score;
}

/* ------------------------------------------------------------------ */
/* 9. function pointers - tests indirect call analysis                 */
/* ------------------------------------------------------------------ */

typedef int (*binary_op_t)(int, int);

int apply(binary_op_t op, int a, int b) {
    return op(a, b);
}

int dispatch_op(int opcode, int a, int b) {
    static binary_op_t table[] = { add, sub, mul };
    if (opcode < 0 || opcode > 2)
        return -1;
    return table[opcode](a, b);
}

/* ------------------------------------------------------------------ */
/* 10. mixed complexity - realistic function for end-to-end test       */
/* ------------------------------------------------------------------ */

/*
 * insertion sort - combines loops, comparisons, pointer writes.
 * good end-to-end test for the full decompilation pipeline.
 */
void insertion_sort(int *arr, int n) {
    for (int i = 1; i < n; i++) {
        int key = arr[i];
        int j   = i - 1;
        while (j >= 0 && arr[j] > key) {
            arr[j + 1] = arr[j];
            j--;
        }
        arr[j + 1] = key;
    }
}

/*
 * binary search - tests loop with two-branch exit condition.
 */
int binary_search(const int *arr, int n, int target) {
    int lo = 0, hi = n - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (arr[mid] == target)
            return mid;
        if (arr[mid] < target)
            lo = mid + 1;
        else
            hi = mid - 1;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* main - drives all tests and prints results                          */
/* ------------------------------------------------------------------ */

int main(void) {
    /* arithmetic */
    printf("add(3,4)=%d\n",       add(3, 4));
    printf("sub(10,3)=%d\n",      sub(10, 3));
    printf("mul(6,7)=%d\n",       mul(6, 7));
    printf("div_by_7(49)=%d\n",   div_by_7(49));
    printf("mod_by_3(11)=%d\n",   mod_by_3(11));

    /* bitwise */
    printf("bit_and(0xF0,0xFF)=0x%X\n", bit_and(0xF0, 0xFF));
    printf("shl(1,8)=%u\n",             shl(1, 8));
    printf("count_bits(255)=%u\n",      count_bits(255));
    printf("mul_by_16(3)=%u\n",         mul_by_16(3));

    /* control flow */
    printf("max(5,9)=%d\n",             max(5, 9));
    printf("classify(42)=%s\n",         classify_int(42));
    printf("abs_val(-7)=%d\n",          abs_val(-7));

    /* switch */
    printf("day_name(3)=%s\n",          day_name(3));
    printf("sparse_switch(100)=%d\n",   sparse_switch(100));

    /* loops */
    printf("sum_range(10)=%d\n",        sum_range(10));
    printf("fib(10)=%d\n",              fib(10));
    printf("factorial(6)=%d\n",         factorial(6));

    /* parity via mutual recursion */
    printf("is_even(4)=%d\n",           is_even(4));
    printf("is_odd(7)=%d\n",            is_odd(7));

    /* pointers */
    int a = 3, b = 7;
    swap(&a, &b);
    printf("swap: a=%d b=%d\n", a, b);

    int va[] = {1, 2, 3}, vb[] = {4, 5, 6};
    printf("dot_product=%d\n", dot_product(va, vb, 3));

    /* struct */
    vec3_t u = {1, 2, 3}, v = {4, 5, 6};
    vec3_t w = vec3_add(u, v);
    printf("vec3_add=(%d,%d,%d)\n", w.x, w.y, w.z);
    printf("vec3_dot=%d\n", vec3_dot(u, v));

    /* function pointer dispatch */
    printf("apply(add,10,5)=%d\n",      apply(add, 10, 5));
    printf("dispatch_op(1,10,3)=%d\n",  dispatch_op(1, 10, 3));

    /* sorting */
    int arr[] = {5, 3, 8, 1, 9, 2, 7, 4, 6};
    int n = (int)(sizeof(arr) / sizeof(arr[0]));
    insertion_sort(arr, n);
    printf("sorted: ");
    for (int i = 0; i < n; i++)
        printf("%d ", arr[i]);
    printf("\n");

    printf("binary_search(7)=%d\n", binary_search(arr, n, 7));
    printf("binary_search(99)=%d\n", binary_search(arr, n, 99));

    return 0;
}
