#!/usr/bin/env python3

for bits in range(10):
    count = 2 << bits
    print('#define CHECK_{}_BITS_LEAKAGE() '.format(bits + 1), end='')
    for cnt in range(1, count + 1):
        print('INIT_INPUT({}) '.format(cnt), end='')
    print('\\\n\\\nassert( \\\n  ', end='')

    start = True
    for cnt in range(1, count):
        for cmp in range(cnt + 1, count + 1):
            if not start:
                print('\\\n  && ', end='')
            else:
                start = False
            print('OUTPUTS_EQUAL(input{}, input{})'.format(cnt, cmp), end='')
    print('\\\n);\n')
