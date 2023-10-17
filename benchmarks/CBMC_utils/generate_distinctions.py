#!/usr/bin/env python3

for bits in range(8):
    count = 2 << bits
    print('#define CHECK_{}_BITS_LEAKAGE() CHECK_DISTINCTIONS_INIT({})'.format(bits + 1, count), end='')
    for cnt in range(count, 1, -1):
        print(' \\\nCHECK_DISTINCTIONS({}, {})'.format(cnt - 1, cnt), end='')
    print('\n')
