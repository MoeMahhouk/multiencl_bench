/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>
#include <string.h>
#include <assert.h>


# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave1_u.h"
#include "Enclave2_u.h"

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include <errno.h>
#include <stdlib.h>
#include <math.h>

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
sgx_enclave_id_t global_eid2 = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE1_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    ret = sgx_create_enclave(ENCLAVE2_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid2, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s\n", str);
}

void ocall_empty_call() {

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;	
    ret = ecall_do_nothing(global_eid2);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        exit(1);
    }
}

void ocall_with_args(uint8_t *a , size_t len) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;	
    ret = ecall_do_nothing_with_args(global_eid2, a, len);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        exit(1);
    }

}

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

#define SEC_TO_NS_FACTOR 1000000000LL

#define TEST_WARMUP_SECS 5

#define TEST_RUNS 1000

#define TEST1_INVOCATIONS 1000

#define TEST2_ARG_SIZE 1
#define TEST2_INVOCATIONS 500

#define TEST3_ARG_SIZE 8
#define TEST3_INVOCATIONS 500

#define TEST4_ARG_SIZE 64
#define TEST4_INVOCATIONS 500

#define TEST5_ARG_SIZE 512
#define TEST5_INVOCATIONS 500

#define TEST6_ARG_SIZE 4*1024
#define TEST6_INVOCATIONS 500

#define TEST7_ARG_SIZE 32*1024
#define TEST7_INVOCATIONS 500

#define TEST8_ARG_SIZE 256*1024
#define TEST8_INVOCATIONS 300

#define TEST9_ARG_SIZE 2*1024*1024
#define TEST9_INVOCATIONS 145

#define TEST10_ARG_SIZE 16*1024*1024
#define TEST10_INVOCATIONS 50

#define TEST11_ARG_SIZE 128*1024*1024
#define TEST11_INVOCATIONS 5


#define MAX_ARG_SIZE TEST11_ARG_SIZE
#define NUMBER_TESTS 9

// macro for testing. Advantage over using a function: shared and reused variables and no need for callbacks and such
#define EXECUTE_TEST(test_name, function_name, function_call, runs, invocations) do { \
    printf("Cleanup for next test\n"); \
    memset(timings, 0, runs * 2 * sizeof(struct timespec)); /* zero indicates error */ \
 \
    printf("%s: %s with %u invocations and %u runs\n", test_name, function_name, invocations, runs); \
    /* Warmup phase */ \
    clock_gettime(CLOCK_MONOTONIC_RAW, &warmup); \
    warmup_start_ns = warmup.tv_sec * SEC_TO_NS_FACTOR + warmup.tv_nsec; \
    do { \
        ret = function_call; \
        if (ret != SGX_SUCCESS) { \
            print_error_message(ret); \
            exit(1); \
        } \
        clock_gettime(CLOCK_MONOTONIC_RAW, &warmup); \
    } while ((warmup.tv_sec * SEC_TO_NS_FACTOR + warmup.tv_nsec - warmup_start_ns) < (TEST_WARMUP_SECS * SEC_TO_NS_FACTOR)); \
 \
    /* Test start */ \
    for (run = 0; run < runs; run++) { \
        clock_gettime(CLOCK_MONOTONIC_RAW, timings + (run * 2)); /* start time */ \
 \
        for (i = 0; i < invocations; i++) { \
            ret = function_call; \
            if (ret != SGX_SUCCESS) { \
                print_error_message(ret); \
                exit(1); \
            } \
        } \
 \
        clock_gettime(CLOCK_MONOTONIC_RAW, timings + (run * 2) + 1); /* end time */ \
    } \
    /* Test end */ \
 \
    /* Evaluation */ \
    printf("%s: %s results\n", test_name, function_name); \
    error = false; \
    elapsed_ns_total = 0; \
    /* calculate each run time and the total value for mean calculation */ \
    for (run = 0; run < runs; run++) { \
        start = timings + (run * 2); \
        end = timings + (run * 2 + 1); \
 \
        if (start->tv_sec == 0 && start->tv_nsec == 0) { \
            error = true; \
            printf("Start time of run %u is invalid\n", run); \
            break; \
        } \
        if (end->tv_sec == 0 && end->tv_nsec == 0) { \
            error = true; \
            printf("End time of run %u is invalid\n", run); \
            break; \
        } \
 \
        /* keep invocation factor of values to reduce arithmetic errors */ \
        elapsed_ns[run] = (end->tv_sec - start->tv_sec) * SEC_TO_NS_FACTOR + end->tv_nsec - start->tv_nsec; \
        elapsed_ns_total += elapsed_ns[run]; \
    } \
 \
    /* get mean and standard deviation */ \
    if (!error) { \
        mean[test] = ((long double) elapsed_ns_total) / runs; \
        variance = 0; \
        for (run = 0; run < runs; run++) { \
            variance += pow(elapsed_ns[run] - mean[test], 2); \
        } \
        deviation[test] = sqrt(variance / runs); \
 \
        /* remove invocation factor */ \
        mean[test] = roundl(mean[test] / invocations); \
        deviation[test] = roundl(deviation[test] / invocations); \
 \
        /* print results */ \
        printf("Each call took %.0Lfns (+- %.0Lfns standard deviation between runs)\n", mean[test], deviation[test]); \
        test++; \
    } \
} while (false)

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);


    printf("size of float = %zu, double = %zu and long double = %zu   ..\n", sizeof(float), sizeof(double), sizeof(long double));

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }
    
    // measurement preparations
    printf("Test preparations\n");
    sgx_status_t ret;
    ret = ecall_prepare_dummy_array(global_eid, MAX_ARG_SIZE);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        exit(1);
    }

    // Warmup times
    struct timespec warmup;
    uint64_t warmup_start_ns;

    // Timings
    struct timespec *timings = (timespec *) malloc(TEST_RUNS * 2 * sizeof(struct timespec)); // start and end times
    if (timings == NULL) {
        printf("Could not malloc timings array\n");
        return -1;
    }
    uint64_t *elapsed_ns = (uint64_t *) malloc(TEST_RUNS * sizeof(uint64_t));
    if (elapsed_ns == NULL) {
        printf("Could not malloc elapsed time array\n");
        return -1;
    }
    uint64_t elapsed_ns_total;
    struct timespec *start, *end;

    // local variables
    bool error;
    uint32_t run, i, test = 0;
    long double variance;
    long double mean[NUMBER_TESTS], deviation[NUMBER_TESTS];

    // TEST 1

    EXECUTE_TEST("TEST1", "ecall_without_args()", (ecall_without_args(global_eid)), TEST_RUNS, TEST1_INVOCATIONS);

    // TEST 2

    EXECUTE_TEST("TEST2", "ecall_with_args(" TOSTRING(TEST2_ARG_SIZE) " bytes)", (ecall_with_args(global_eid, TEST2_ARG_SIZE)), TEST_RUNS, TEST2_INVOCATIONS);

    // TEST 3

    EXECUTE_TEST("TEST3", "ecall_with_args(" TOSTRING(TEST3_ARG_SIZE) " bytes)", (ecall_with_args(global_eid, TEST3_ARG_SIZE)), TEST_RUNS, TEST3_INVOCATIONS);

    // TEST 4

    EXECUTE_TEST("TEST4", "ecall_with_args(" TOSTRING(TEST4_ARG_SIZE) " bytes)", (ecall_with_args(global_eid, TEST4_ARG_SIZE)), TEST_RUNS, TEST4_INVOCATIONS);

    // TEST 5

    EXECUTE_TEST("TEST5", "ecall_with_args(" TOSTRING(TEST5_ARG_SIZE) " bytes)", (ecall_with_args(global_eid, TEST5_ARG_SIZE)), TEST_RUNS, TEST5_INVOCATIONS);

    // TEST 6

    EXECUTE_TEST("TEST6", "ecall_with_args(" TOSTRING(TEST6_ARG_SIZE) " bytes)", (ecall_with_args(global_eid, TEST6_ARG_SIZE)), TEST_RUNS, TEST6_INVOCATIONS);

    // TEST 7

    EXECUTE_TEST("TEST7", "ecall_with_args(" TOSTRING(TEST7_ARG_SIZE) " bytes)", (ecall_with_args(global_eid, TEST7_ARG_SIZE)), TEST_RUNS, TEST7_INVOCATIONS);

    // TEST 8

    EXECUTE_TEST("TEST8", "ecall_with_args(" TOSTRING(TEST8_ARG_SIZE) " bytes)", (ecall_with_args(global_eid, TEST8_ARG_SIZE)), TEST_RUNS, TEST8_INVOCATIONS);

    // TEST 9

    EXECUTE_TEST("TEST9", "ecall_with_args(" TOSTRING(TEST9_ARG_SIZE) " bytes)", (ecall_with_args(global_eid, TEST9_ARG_SIZE)), TEST_RUNS, TEST9_INVOCATIONS);

    // TEST 10
    // TODO crashes

    //EXECUTE_TEST("TEST10", "ecall_with_args(" TOSTRING(TEST10_ARG_SIZE) " bytes)", (ecall_with_args(global_eid, TEST10_ARG_SIZE)), TEST_RUNS, TEST10_INVOCATIONS);

    // TEST 11

    //EXECUTE_TEST("TEST11", "ecall_with_args(" TOSTRING(TEST11_ARG_SIZE) " bytes)", (ecall_with_args(global_eid, TEST11_ARG_SIZE)), TEST_RUNS, TEST11_INVOCATIONS);

    /* Destroy the enclaves */
    sgx_destroy_enclave(global_eid);
    sgx_destroy_enclave(global_eid2);

    printf("Test results as CSV:\n");
    printf("timing, deviation\n");
    for (i = 0; i < NUMBER_TESTS; i++) {
        printf("%.0Lf, %.0Lf\n", mean[i], deviation[i]);
    }

    printf("Enter a character before exit ...\n");
    getchar();
    return 0;
}

