// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <vld.h>

#include "ctest.h"

int main(void)
{
    size_t failedTestCount = 0;
    CTEST_RUN_TEST_SUITE(cord_socket_winsock_ut, failedTestCount);
    return failedTestCount;
}
