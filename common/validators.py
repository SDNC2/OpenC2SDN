'''
Data type validators for Floodlight Phantom App
Created on April 12, 2016

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

import re
import simplejson as json
import copy
from inspect import currentframe, getframeinfo

import openflow_utils

_DPID_REGEX = re.compile("([0-9A-Fa-f]{2}:){7}[0-9a-fA-F]{2}$|([0-9A-Fa-f]{2}-){7}[0-9a-fA-F]{2}$")
_SCOPED_DPID_REGEX = re.compile("(?<=^dpid:)[0-9a-fA-F:-]+$")
_MAC_REGEX = re.compile("([0-9A-Fa-f]{2}:){5}[0-9a-fA-F]{2}$|([0-9A-Fa-f]{2}-){5}[0-9a-fA-F]{2}$")
_IPV4_REGEX = re.compile("([0-9]{1,3}\\.){3}[0-9]{1,3}$")
_IPV6_FULL_REGEX = re.compile("([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$")
_IPV6_GROUP_REGEX = re.compile("[0-9a-fA-F]{1,4}$")


def _validate_int(value, min_inclusive, max_inclusive):
    if isinstance(value, int):
        int_value = value
    elif isinstance(value, basestring):
        if value.isdigit():
            int_value = int(value)
        else:
            return False

    return min_inclusive <= int_value <= max_inclusive


def validate_asn(value):
    return _validate_int(value, 0, 65535)


def validate_vlan_id(value):
    return _validate_int(value, 0, 4095)


def validate_dpid(value):
    if isinstance(value, basestring):
        result = _DPID_REGEX.match(value)
        return result is not None

    return False


def validate_scoped_dpid(value):
    if isinstance(value, basestring):
        match = _SCOPED_DPID_REGEX.search(value)
        return (match is not None) and validate_dpid(match.group(0))

    return False


def validate_port_id(value):
    return openflow_utils.portname_to_portnum(value) is not None


def validate_mac(value):
    if isinstance(value, basestring):
        result = _MAC_REGEX.match(value)
        return result is not None

    return False


def validate_ip4(value):
    if isinstance(value, basestring):
        if _IPV4_REGEX.match(value) is not None:
            return all(_validate_int(x, 0, 255) for x in value.split('.'))

    return False


def validate_ip6(value):
    if isinstance(value, basestring):
        result = _IPV6_FULL_REGEX.match(value)
        if result is not None:
            return True

        if ":::" in value:
            return False

        ipv6_halves = value.split("::")
        if len(ipv6_halves) == 2:
            if ipv6_halves[0] == "":
                groups = []
            else:
                groups = ipv6_halves[0].split(":")

            if ipv6_halves[1] != "":
                groups = groups + ipv6_halves[1].split(":")

            return len(groups) < 8 and all(_IPV6_GROUP_REGEX.match(grp) for grp in groups)

    return False


def validate_ip(value):
    return validate_ip4(value) or validate_ip6(value)


def validate_cidr(value):
    if isinstance(value, basestring):
        parts = value.split("/")

        if len(parts) != 2:
            return False

        if validate_ip4(parts[0]):
            return _validate_int(parts[1], 0, 32)

        if validate_ip6(parts[0]):
            return _validate_int(parts[1], 0, 64)

    return False


def validate_dataport(value):
    if isinstance(value, basestring):
        try:
            value = json.loads(value)
        except:
            return False

    if not isinstance(value, dict):
        return False

    if "datapath" in value:
        if not validate_scoped_dpid(value["datapath"]):
            return False

    if "port" in value:
        if not validate_port_id(value["port"]):
            return False

    return True


def validate_cybox_address(value, category=None):
    if isinstance(value, basestring):
        try:
            value = json.loads(value)
        except:
            return False

    if not isinstance(value, dict):
        return False

    if "VLAN_Name" in value and not isinstance(value["VLAN_Name"], basestring):
        return False

    if "VLAN_Num" in value and not validate_vlan_id(value["VLAN_Num"]):
        return False

    if category is None:
        category = value.get("category", "ipv4-addr")
    elif "category" in value and value["category"] != category:
        return False

    if "Address_Value" in value:
        av = value["Address_Value"]
        if category == "asn":
            return validate_asn(av)
        if category == "atm":
            print("Warning: Validator does not verify values for 'atm' category cybox:Address")
            return True
        if category == "cidr":
            return validate_cidr(av)
        if category == "email":
            print("Warning: Validator does not verify values for 'email' category cybox:Address")
            return True
        if category == "mac":
            return validate_mac(av)
        if category == "ipv4-addr" or category == "ipv4-net" or category == "ipv4-net-mask":
            return validate_ip4(av)
        if category == "ipv6-addr" or category == "ipv6-net" or category == "ipv6-net-mask":
            return validate_ip6(av)

        print("Warning: Validator does not support '{}' category for cybox:Address".format(category))
        return False  # unknown category

    return True


def validate_cybox_port(value):
    if isinstance(value, basestring):
        try:
            value = json.loads(value)
        except:
            return False

    if not isinstance(value, dict):
        return False

    if "Port_Value" in value and not _validate_int(value["Port_Value"], 1, 65535):
        return False

    if "Layer4_Protocol" in value and not isinstance(value["Layer4_Protocol"], (basestring, dict)):
        return False

    return True


def validate_cybox_socket_address(value):
    if isinstance(value, basestring):
        try:
            value = json.loads(value)
        except:
            return False

    if not isinstance(value, dict):
        return False

    if "IP_Address" in value and not validate_cybox_address(value["IP_Address"]):
        return False

    if "Port" in value and not validate_cybox_port(value["Port"]):
        return False

    return True


def validate_cybox_network_connection(value):
    if isinstance(value, basestring):
        try:
            value = json.loads(value)
        except:
            return False

    if not isinstance(value, dict):
        return False

    if "Layer3_Protocol" in value and not isinstance(value["Layer3_Protocol"], (basestring, dict)):
        return False

    if "Layer4_Protocol" in value and not isinstance(value["Layer4_Protocol"], (basestring, dict)):
        return False

    if "Source_Socket_Address" in value and not validate_cybox_socket_address(value["Source_Socket_Address"]):
        return False

    if "Destination_Socket_Address" in value and not validate_cybox_socket_address(value["Destination_Socket_Address"]):
        return False

    return True


def validate_flow(value):
    if isinstance(value, basestring):
        try:
            value = json.loads(value)
        except:
            return False

    if not isinstance(value, dict):
        return False

    if value.get("Layer2_Protocol", "Ethernet") != "Ethernet":
        return False

    if "Source_Layer2_Address" in value and not validate_cybox_address(value["Source_Layer2_Address"], category="mac"):
        return False

    if "Destination_Layer2_Address" in value and not validate_cybox_address(value["Destination_Layer2_Address"], category="mac"):
        return False

    return validate_cybox_network_connection(value)


def _test_failed(msg, lineno):
    print(msg + ' at line {}'.format(lineno))


def _unit_test_dpid():
    failcnt = 0

    if validate_dpid(""):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    # colons
    if not validate_dpid("01:02:03:ff:FF:06:07:f0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_dpid("001:02:03:ff:FF:06:07:f0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_dpid("00:01:02:03:ff:FF:06:07:f0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_dpid("02:03:ff:FF:06:07:f0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_dpid("0:02:03:ff:FF:06:07:f0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_dpid("01:02:03:ff:FF:06:07:0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    # dashes
    if not validate_dpid("01-02-03-ff-FF-06-07-f0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_dpid("001-02-03-ff-FF-06-07-f0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_dpid("00-01-02-03-ff-FF-06-07-f0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_dpid("0-02-03-ff-FF-06-07-f0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_dpid("01-02-03-ff-FF-06-07-0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    # colon/dash mix
    if validate_dpid("01:02-03-ff-FF-06-07-f0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_dpid("01:02:03:ff:FF:06:07-f0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    # Scoped dpids
    if not validate_scoped_dpid("dpid:01:02:03:ff:FF:06:07:f0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_scoped_dpid(None):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_scoped_dpid(""):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_scoped_dpid({}):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_scoped_dpid("dpid:"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_scoped_dpid("dpid:1"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_scoped_dpid(":01:02:03:ff:FF:06:07:f0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_scoped_dpid("01:02:03:ff:FF:06:07:f0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    return failcnt


def _unit_test_mac():
    failcnt = 0

    if validate_mac(""):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    # colons
    if not validate_mac("01:02:03:ff:FF:f0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_mac("001:02:03:ff:FF:f0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_mac("00:01:02:03:ff:FF:f0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_mac("02:03:ff:FF:f0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_mac("0:02:03:ff:FF:f0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_mac("01:02:03:ff:FF:0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    # dashes
    if not validate_mac("01-02-03-ff-FF-f0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_mac("001-02-03-ff-FF-f0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_mac("00-01-02-03-ff-FF-f0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_mac("0-02-03-ff-FF-f0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_mac("01-02-03-ff-FF-0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    # colon/dash mix
    if validate_mac("01:02-03-ff-FF-f0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_mac("01:02:03:ff:FF-f0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    return failcnt


def _unit_test_ip():
    failcnt = 0

    # IPv4
    if not validate_ip4("127.0.00.1"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_ip4(""):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_ip4("127.0.00.256"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_ip4("1.2.3"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_ip4("1.2.3.4."):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_ip4("f.2.3.4"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_ip4("::"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    # IPv6
    if not validate_ip6("::"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if not validate_ip6("fe80::"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if not validate_ip6("::1"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if not validate_ip6("1:2:3:4:5:6::8"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if not validate_ip6("1:2:3:4:5:6:7:8"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if not validate_ip6("1:2::5:6:fffF:8"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_ip6("1:2:3:4:5:6:7:8:9"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_ip6("1:2:3:4:5:6:7"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_ip6("1:2:3:4:5:6:7:"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_ip6(""):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    # IPv4 or IPv6
    if not validate_ip("::"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if not validate_ip("12.34.56.78"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_ip("1"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    return failcnt


def _unit_test_cidr():
    failcnt = 0

    # IPv4 and mask
    if not validate_cidr("0.0.0.0/0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if not validate_cidr("255.255.255.255/32"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_cidr("255.255.255.255/33"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_cidr("255.255.255.255/-1"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    # IPv6 and mask
    if not validate_cidr("::/64"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if not validate_cidr("::1/0"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_cidr("::/65"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_cidr("::/-1"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    return failcnt


def _unit_test_json():
    failcnt = 0

    # Flow
    good_flow = {
             "Layer2_Protocol": "Ethernet",
             "Layer3_Protocol": "IPv4",
             "Layer4_Protocol": "TCP",
             "Source_Layer2_Address": {"category": "mac", "Address_Value": "01:02:03:04:05:06"},
             "Destination_Layer2_Address": {"category": "mac", "Address_Value": "01:02:03:04:05:06"},
             "Source_Socket_Address": {
                                       "IP_Address": {"category": "ipv4-addr", "Address_Value": "10.0.0.1", "VLAN_Name": "fred", "VLAN_Num": 10},
                                       "Port": {"Port_Value": 121, "Layer4_Protocol": "TCP"}
                                      },
             "Destination_Socket_Address": {
                                       "IP_Address": {"category": "cidr", "Address_Value": "10.0.0.0/8", "VLAN_Name": "fred", "VLAN_Num": 10},
                                       "Port": {"Port_Value": 80, "Layer4_Protocol": "TCP"},
                                           }
           }

    if not validate_flow(good_flow):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if not validate_flow(json.dumps(good_flow)):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if not validate_flow("{}"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if not validate_flow({}):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if validate_flow(""):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    bad_flow = copy.deepcopy(good_flow)
    bad_flow["Destination_Socket_Address"]["IP_Address"]["category"] = "ipv4-addr"
    if validate_flow(bad_flow):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    bad_flow = copy.deepcopy(good_flow)
    bad_flow["Destination_Socket_Address"]["IP_Address"]["Address_Value"] = "127.0.0.1"
    if validate_flow(bad_flow):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    bad_flow = copy.deepcopy(good_flow)
    bad_flow["Source_Socket_Address"]["Port"]["Port_Value"] = "12345678"
    if validate_flow(bad_flow):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    bad_flow = copy.deepcopy(good_flow)
    bad_flow["Source_Layer2_Address"]["Address_Value"] = "10.0.0.1"
    if validate_flow(bad_flow):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    bad_flow = copy.deepcopy(good_flow)
    bad_flow["Destination_Layer2_Address"]["category"] = "ipv4-addr"
    if validate_flow(bad_flow):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    bad_flow = copy.deepcopy(good_flow)
    bad_flow["Destination_Socket_Address"]["IP_Address"]["VLAN_Num"] = "4096"
    if validate_flow(bad_flow):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    # Dataport
    good_dataport = {"datapath": "dpid:00-01-02-03-04-05-06-07", "port": 12}
    if not validate_dataport(good_dataport):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    bad_dataport = copy.deepcopy(good_dataport)
    bad_dataport["datapath"] = "00:01:02:03:04:05:06:07"
    if validate_dataport(bad_dataport):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    bad_dataport = copy.deepcopy(good_dataport)
    bad_dataport["port"] = "this is a bad port identifier"
    if validate_dataport(bad_dataport):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    # Address corner cases
    addr = {"category": "mac", "Address_Value": "01:02:03:04:05:06"}
    if not validate_cybox_address(addr):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    # Unspecified category, defaults to ipv4-addr
    del addr["category"]
    if validate_cybox_address(addr):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    # Tell the validator what type is expected even though unspecified
    if not validate_cybox_address(addr, category="mac"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    # Conflict between expected category and actual category
    addr["category"] = "cidr"
    if validate_cybox_address(addr, category="mac"):
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    return failcnt


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', action='store_true', help='run in pudb')
    args = parser.parse_args()
    if args.d:
        import pudb
        pudb.set_trace()

    failcnt = _unit_test_dpid()
    failcnt = failcnt + _unit_test_mac()
    failcnt = failcnt + _unit_test_ip()
    failcnt = failcnt + _unit_test_cidr()
    failcnt = failcnt + _unit_test_json()

    if failcnt < 1:
        print("ALL TESTS PASSED")
    else:
        print("{} TESTS FAILED".format(failcnt))
