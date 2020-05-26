# Running tests

## running all test with valgrind

ctest -C "debug" -V -T memcheck

## Running individual test with valgrind

valgrind --tool=memcheck --leak-check=yes --show-reachable=yes <test name>