#!/usr/bin/python

import gen
import os
import subprocess

cls = 'Darwin_x86_mach'
header = os.path.join(gen.SRC, 'darwin_x86_mach.h')
target = os.path.join(gen.TARGET, 'darwin_x86_mach_sys.go')

c_template = '''
#include <stdio.h>
#include <%(header)s>

int main() {
    %(body)s
}
'''

if __name__ == '__main__':
    base = os.path.dirname(__file__)
    if base:
        os.chdir(base)

    p = subprocess.Popen(['cpp', '-dM', header], stdout=subprocess.PIPE)
    lines = p.communicate('')[0]
    nums = [line.split(' ')[1] for line in lines.split('\n') if 'NR' in line]
    body = ' '.join(['printf("%s = %%d\\n", %s);' % (num, num) for num in nums])
    c = c_template % {
        'header': header,
        'body': body,
    }
    cfile = '/tmp/ghostrace-parse.c'
    cbin = '/tmp/ghostrace-parse'
    with open(cfile, 'w') as f:
        f.write(c)
    p = subprocess.Popen(['gcc', cfile, '-o', cbin, '-I', os.getcwd()], stdout=subprocess.PIPE)
    print p.communicate('')[0]
    p = subprocess.Popen(cbin, stdout=subprocess.PIPE)
    values = p.communicate('')[0].split('\n')
    os.unlink(cfile)
    os.unlink(cbin)
    syscalls = [line.split(' = ', 1) for line in values if ' = ' in line]
    syscalls = [(name.replace('__NR_', '', 1), value) for name, value in syscalls]
    # dedup
    syscalls = [(v, k) for k, v in dict([(v, k) for k, v in syscalls]).items()]

    num_len = max(len(str(num)) for name, num in syscalls) + 1
    lines = []
    for name, num in syscalls:
        num = (str(num) + ':').ljust(num_len)
        lines.append(gen.LINE_TEMPLATE % {'name': name, 'num': num})

    with open(target, 'w') as f:
        f.write(gen.FILE_TEMPLATE % {'cls': cls, 'lines': '\n\t'.join(lines)})
