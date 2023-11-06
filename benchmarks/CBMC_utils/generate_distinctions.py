#!/usr/bin/env python3

for bits in range(11):
    count = 2 << bits
    print('#define CHECK_{}_BITS_LEAKAGE() \\\n  '.format(bits + 1), end='')
    for cnt in range(1, count + 1):
        print('INIT_INPUT({}) '.format(cnt), end='')
    print(' \\\n  ', end='')
    for cnt in range(1, count + 1):
        print('GENERATE_OUTPUT({}) '.format(cnt), end='')
    print('\\\n  \\\n  __CPROVER_assume( \\\n    ', end='')

    start = True
    for cnt in range(1, count):
        for cmp in range(cnt + 1, count + 1):
            if not start:
                print('\\\n    && ', end='')
            else:
                start = False
            print('!OUTPUTS_EQUAL({}, {})'.format(cnt, cmp), end='')
    print('\\\n  ); \\')

    final = count + 1
    print('  INIT_INPUT({}) GENERATE_OUTPUT({}) \\'.format(final, final))
    print('  __CPROVER_assert( \\')
    print('    OUTPUTS_EQUAL({}, 1)'.format(final), end='')
    for cnt in range(2, count + 1):
      print(' || OUTPUTS_EQUAL({}, {})'.format(final, cnt), end='')
    print(', \\\n    "Leak bound <= {} bits" \\\n  );\n'.format(bits + 1))
