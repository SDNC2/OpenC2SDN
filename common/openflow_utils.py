'''
Openflow utilities
Created on April 15, 2016

Distribution Statement A: Approved for public release: distribution unlimited. ; May 3, 2016

This software was developed under the authority of SPAWAR Systems Center
Atlantic by employees of the Federal Government in the course of their official
duties. Pursuant to title 17 Section 105 of the United States Code this
software is not subject to copyright protection and is in the public domain.
The Government assumes no responsibility whatsoever for its use by other
parties, and the software is provided "AS IS" without warranty or guarantee of
any kind, express or implied, including, but not limited to, the warranties of
merchantability and of fitness for a particular purpose. In no event shall the
Government be liable for any claim, damages or other liability, whether in an
action of contract, tort or other dealings in the software.   The Government
has no obligation hereunder to provide maintenance, support, updates,
enhancements, or modifications.  We would appreciate acknowledgement if the
software is used. This software can be redistributed and/or modified freely
provided that any derivative works bear some notice that they are derived from
it, and any modified versions bear some notice that they have been modified.

@author: Randall Sharo <randall.sharo@navy.mil>
@date April 27, 2016
'''
from inspect import currentframe, getframeinfo
import re

_OFP_PORT_NAMES = {
                   "UNSET": -9, "IN_PORT": -8, "TABLE": -7,
                   "NORMAL": -6, "FLOOD": -5, "ALL": -4,
                   "CONTROLLER": -3, "LOCAL": -2, "ANY": -1
                 }
_OFP_PORT_NUMBERS = {v: k for k, v in _OFP_PORT_NAMES.items()}


def dpid_to_datapath(val):
    return "dpid:{}".format(val)


def datapath_to_dpid(val):
    return re.search('(?<=^dpid:)[0-9a-fA-F:-]+$', val).group(0).replace('-', ':')


def portname_to_portnum(name):
    if isinstance(name, basestring):
        try:
            return int(name)
        except ValueError:
            return _OFP_PORT_NAMES.get(name.upper(), None)

    elif isinstance(name, (int, long)):
        return name

    return None


def portnum_to_portname(num):
    if isinstance(num, basestring):
        try:
            num = int(num)
        except ValueError:
            return None

    if isinstance(num, (int, long)):
        return _OFP_PORT_NUMBERS.get(num, str(num))

    return None


def _test_failed(msg, lineno):
    print(msg + ' at line {}'.format(lineno))


def _unit_test_utils():
    failcnt = 0

    # Portname to Portnum
    if portname_to_portnum(None) is not None:
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if portname_to_portnum("") is not None:
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if portname_to_portnum(["local"]) is not None:
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if portname_to_portnum("hamburger") is not None:
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if portname_to_portnum(8192) != 8192:
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if portname_to_portnum("1291") != 1291:
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if portname_to_portnum("loCAL") != -2:
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if portname_to_portnum("-3") != -3:
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    # Portnum to Portname
    if portnum_to_portname(None) is not None:
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if portnum_to_portname("") is not None:
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if portnum_to_portname("hamburger") is not None:
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if portnum_to_portname(8192) != "8192":
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if portnum_to_portname("1291") != "1291":
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if portnum_to_portname("local") is not None:
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if portnum_to_portname("-3") != "CONTROLLER":
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    return failcnt

if __name__ == '__main__':
    failcnt = _unit_test_utils()

    if failcnt < 1:
        print("ALL TESTS PASSED")
    else:
        print("{} TESTS FAILED".format(failcnt))
