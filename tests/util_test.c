#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <sys/time.h>

#define COLD /**/
int debug = 0;
const unsigned char zeroes[16] = {0};

#include "util.c"

static void
test_do_ntohs(void **state)
{
    unsigned char s[2] = {0x05, 0x39};
    unsigned short d;
    DO_NTOHS(d, &s);
    assert_int_equal(d, 1337);
}

static void
test_do_ntohl(void **state)
{
    unsigned char s[4] = {0xDA, 0xEB, 0xA0, 0x00};
    unsigned int d;
    DO_NTOHL(d, &s);
    assert_int_equal(d, 3672875008);
}

static void
test_do_htons(void **state)
{
    unsigned short s = 1337;
    unsigned char d[2] = {0};
    DO_HTONS(&d, s);
    assert_int_equal(d[0], 0x05);
    assert_int_equal(d[1], 0x39);
}

static void
test_do_htonl(void **state)
{
    unsigned int s = 3672875008;
    unsigned char d[4] = {0};
    DO_HTONL(&d, s);
    assert_int_equal(d[0], 0xDA);
    assert_int_equal(d[1], 0xEB);
    assert_int_equal(d[2], 0xA0);
    assert_int_equal(d[3], 0x00);
}

static void
test_roughly_pos(void **state)
{
    int v = 42;
    int r = roughly(v);
    assert_in_range(r, v * 3/4, v * 3/4 + v/2 - 1);
}

static void
test_roughly_neg(void **state)
{
    int v = -42;
    int r = roughly(v);
    assert_in_range(r, v * 3/4 + (v / 2) - 1, v * 3/4);
}

static void
test_timeval_minus(void **state)
{
    struct timeval d;
    struct timeval s1 = {.tv_sec = 10, .tv_usec = 10},
        s2 = {.tv_sec = 2, .tv_usec = 2};
    timeval_minus(&d, &s1, &s2);
    assert_int_equal(d.tv_sec, 8);
    assert_int_equal(d.tv_usec, 8);
}

static void
test_timeval_minus_msec(void **state)
{
    struct timeval s1 = {.tv_sec = 42, .tv_usec = 42 };
    struct timeval s2 = {.tv_sec = 420000000, .tv_usec = 10000};
    assert_int_equal(timeval_minus_msec(&s1, &s2), 0);
    assert_int_equal(timeval_minus_msec(&s2, &s1), 2000000000);
    s2.tv_sec = 42000;
    assert_int_equal(timeval_minus_msec(&s2, &s1), 41958009);
    s1.tv_sec = 42000;
    assert_int_equal(timeval_minus_msec(&s1, &s2), 0);
    assert_int_equal(timeval_minus_msec(&s2, &s1), 9);
}

static void
test_timeval_add_msec(void **state)
{
    struct timeval d, s = {.tv_sec = 42, .tv_usec = 42};
    timeval_add_msec(&d, &s, 42);
    assert_int_equal(d.tv_sec, 42);
    assert_int_equal(d.tv_usec, 42042);
    timeval_add_msec(&d, &s, 1337);
    assert_int_equal(d.tv_sec, 43);
    assert_int_equal(d.tv_usec, 337042);
}

static void
test_timeval_compare(void **state)
{
    struct timeval s1 = {.tv_sec = 0, .tv_usec = 0xC0FE},
        s2 = {.tv_sec = 1, .tv_usec = 0xCAFE};
    assert_int_equal(timeval_compare(&s1, &s2), -1);
    assert_int_equal(timeval_compare(&s2, &s1), 1);
    assert_int_equal(timeval_compare(&s1, &s1), 0);
    s1.tv_sec = 1;
    assert_int_equal(timeval_compare(&s1, &s2), -1);
    assert_int_equal(timeval_compare(&s2, &s1), 1);
}

static void
test_parse_nat(void **state)
{
    assert_int_equal(parse_nat("0755"), 0755);
    assert_int_equal(parse_nat("42"), 42);
    assert_int_equal(parse_nat("0xffff"), 0xffff);
    assert_int_equal(parse_nat("0xFFFF"), 0xFFFF);
    assert_true(parse_nat("coffee") < 0);
}

static void
test_parse_thousands(void **state)
{
    /* strings are null-terminated */
    assert_int_equal(parse_thousands("1337"), 1337000);
    assert_int_equal(parse_thousands("1337."), 1337000);
    assert_int_equal(parse_thousands(".1337"), 133);
    assert_int_equal(parse_thousands("  \t42.1337 \t"), 42133);
    assert_int_equal(parse_thousands("1.1337"), 1133); /* rounding down */
    assert_int_equal(parse_thousands("36.15"), 36150);
    assert_true(parse_thousands("42.1337dragons") < 0);
    assert_true(parse_thousands("stuff") < 0);
}

static void
test_in_prefix(void **state)
{
    unsigned char address[16] = {0xFE, 0x80, 0xDE, 0xC1};
    unsigned char prefix[16]  = {0xFE, 0x80, 0xDE, 0xC1};
    assert_true(in_prefix(address, prefix, 32));
    assert_true(in_prefix(address, prefix, 14));
    address[3] = 0x00;
    assert_false(in_prefix(address, prefix, 32));
    address[0] = 0xAD;
    assert_false(in_prefix(address, prefix, 32));
}

static void
test_prefix_cmp(void **state)
{
    unsigned char p1[16] = {0xFE, 0x80};
    unsigned char p2[16] = {0};
    enum prefix_status ps;

    ps = prefix_cmp(p1, 16, p2, 0);
    assert_int_equal(ps, PST_MORE_SPECIFIC);
    ps = prefix_cmp(p2, 0, p1, 16);
    assert_int_equal(ps, PST_LESS_SPECIFIC);
    ps = prefix_cmp(p1, 16, p2, 32);
    assert_int_equal(ps, PST_DISJOINT);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_do_ntohs),
        cmocka_unit_test(test_do_ntohl),
        cmocka_unit_test(test_do_htons),
        cmocka_unit_test(test_do_htonl),
        cmocka_unit_test(test_roughly_pos),
        cmocka_unit_test(test_roughly_neg),
        cmocka_unit_test(test_timeval_minus),
        cmocka_unit_test(test_timeval_minus_msec),
        cmocka_unit_test(test_timeval_add_msec),
        cmocka_unit_test(test_timeval_compare),
        cmocka_unit_test(test_parse_nat),
        cmocka_unit_test(test_parse_thousands),
        cmocka_unit_test(test_in_prefix),
        cmocka_unit_test(test_prefix_cmp),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
