#!/usr/bin/env python3

for bits in range(16):
    count = 2 << bits
    print('#define CHECK_{}_BITS_LEAKAGE() '.format(bits + 1), end='')
    for cnt in range(1, count + 1):
        print('INIT_INPUT({}) '.format(cnt), end='')
    print('\\\n', end='')

    start = True
    for cnt in range(1, count):
        if not start:
            print('\\\n', end='')
        else:
            start = False
        print('assert(OUTPUTS_EQUAL(input{}, input{})); '.format(cnt, cnt + 1), end='')
    print('\n')
