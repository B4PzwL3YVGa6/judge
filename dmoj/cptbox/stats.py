from __future__ import print_function

import logging
import os
import re
import sys

from dmoj.cptbox.handlers import ALLOW, DISALLOW
# noinspection PyUnresolvedReferences
from dmoj.cptbox.syscalls import *

import uuid
from functools import partial
from collections import Counter

log = logging.getLogger('dmoj.security')


class StatsSecurity(dict):
    def __init__(self, proxy, dst='/code/syscall-stats'):
        super(StatsSecurity, self).__init__()
        self.counter = Counter()
        self.logfile = os.path.join(dst, 'syscalls-' + str(uuid.uuid4()) + '.log')

        def log(syscall, debugger, *args, **kwargs):
            self.counter[syscall] += 1
            handler = proxy.get(syscall, DISALLOW)
            if callable(handler):
                return handler(debugger, *args, **kwargs)
            elif handler == ALLOW:
                return True
            else:
                return False

        def save():
            with open(self.logfile, 'w') as f:
                for syscall, count in self.counter.items():
                    print('%d %d' % (syscall, count), file=f)
            print('Wrote syscall counts to %s' % self.logfile)

        self[-1] = save

        for syscall in xrange(500):
            self[syscall] = partial(log, syscall)

