from __future__ import print_function

from pykdump.API import *

import sys

def revs_x86():
    print ("""
** function parameters for x86_64 **
%rdi - 1st argument (%rdi:64, %edi:32, %di:16, %dl:8)
%rsi - 2nd argument (%rsi:64, %esi:32, %si:16, %sl:8)
%rdx - 3rd argument (%rdx:64, %edx:32, %dx:16, %dl:8)
%rcx - 4th argument (%rcx:64, %ecx:32, %cx:16, %cl:8)
%r8 - 5th argument (%r8:64, %r8d:32, %r8w:16, %r8b:8)
%r9 - 6th argument (%r9:64, %r9d:32, %r9w:16, %r9b:8)
%rsp - Stack pointer
%rax - Return value""")


def revs():
    if (sys_info.machine in ("x86_64", "i386", "i686", "athlon")):
        revs_x86()

if ( __name__ == '__main__'):
    revs()
