'''
Firewall REST API for Floodlight SDN controller
Created on March 23, 2016

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
import floodlight_rest
import re
import socket
import openflow_utils

_ETH_TYPE_IPV4 = 0x800
_ETH_TYPE_ARP = 0x806
_L4_PROTOS = {
               1: "ICMP", 2: "IGMP", 4: "IPv4", 6: "TCP",
               17: "UDP", 41: "IPv6", 47: "GRE", 51: "AH", 58: "ICMPv6"
            }


def protonum_to_protoname(num):
    return _L4_PROTOS.get(num, num)


def ruleid_to_activityid(val):
    return "firewall_rule:{}".format(val)


def activityid_to_ruleid(val):
    return int(re.search('(?<=^firewall_rule:)[0-9-]*$', val).group(0))


def _normalize_action_name(action):
    if isinstance(action, basestring):
        action = action.upper()
        if action == "ALLOW" or action == "ACCEPT":
            return "ALLOW"
        elif action == "DENY" or action == "DROP":
            return "DENY"

    return None


def _compare_key(dicta, dictb, key):
    if key not in dicta or key not in dictb:
        return False

    a = dicta[key]
    b = dictb[key]

    try:
        if isinstance(a, (int, long, float, complex)) and isinstance(b, basestring):
            return type(a)(b) == a

        if isinstance(b, (int, long, float, complex)) and isinstance(a, basestring):
            return type(b)(a) == b

    except ValueError:
        return False

    return a == b


def _params_to_firewall_in(action, param):
    rule = {"action": _normalize_action_name(action)}
    rule.update(param)

    if "src-inport" in param:
        rule["src-inport"] = openflow_utils.portname_to_portnum(rule["src-inport"])

    if "switchid" in param:
        rule["switchid"] = openflow_utils.datapath_to_dpid(param["switchid"])

    return rule


def _firewall_out_to_params(rule):
    # Note: FL Firewall always reports all fields. No need to check for key existence.
    param = {
             "action": rule["action"],
             "priority": rule["priority"],
             "activityid": ruleid_to_activityid(rule["ruleid"])
            }

    if not rule["any_dpid"]:
        param["switchid"] = openflow_utils.dpid_to_datapath(rule["dpid"])

    if not rule["any_in_port"]:
        pname = openflow_utils.portnum_to_portname(rule["in_port"])
        if pname is not None:
            param["src-inport"] = pname

    if not rule["any_dl_src"]:
        param["src-mac"] = rule["dl_src"]

    if not rule["any_dl_dst"]:
        param["dst-mac"] = rule["dl_dst"]

    if not rule["any_dl_type"]:
        param["dl-type"] = "ARP" if int(rule.get("dl_type")) == _ETH_TYPE_ARP else "IPv4"

    if not rule["any_nw_src"]:
        if int(rule["nw_src_maskbits"]) == 32:
            param["src-ip"] = rule["nw_src_prefix"]
        else:
            param["src-ip"] = "{}/{}".format(rule["nw_src_prefix"], rule["nw_src_maskbits"])

    if not rule["any_nw_dst"]:
        if int(rule["nw_dst_maskbits"]) == 32:
            param["dst-ip"] = rule["nw_dst_prefix"]
        else:
            param["dst-ip"] = "{}/{}".format(rule["nw_dst_prefix"], rule["nw_dst_maskbits"])

    if not rule["any_tp_src"]:
        param["tp-src"] = rule["tp_src"]

    if not rule["any_tp_dst"]:
        param["tp-dst"] = rule["tp_dst"]

    if not rule["any_nw_proto"]:
        l4proto = protonum_to_protoname(rule.get("nw_proto"))
        param["nw-proto"] = l4proto

    return param


def _params_to_firewall_out(action, param):
    rule = {
             "action": "DROP",
             "any_dl_dst": True, "any_dl_src": True, "any_dl_type": True,
             "any_dpid": True, "any_in_port": True,
             "any_nw_dst": True, "any_nw_proto": True, "any_nw_src": True,
             "any_tp_dst": True, "any_tp_src": True,
             "dl_dst": "00:00:00:00:00:00", "dl_src": "00:00:00:00:00:00", "dl_type": 0,
             "dpid": "00:00:00:00:00:00:00:00", "in_port": -1,
             "nw_dst_maskbits": 0, "nw_dst_prefix": "0.0.0.0", "nw_proto": 0,
             "nw_src_maskbits": 0, "nw_src_prefix": "0.0.0.0", "priority": 0,
             "tp_dst": 0, "tp_src": 0
           }

    action = _normalize_action_name(action)
    if action:
        # Openc2 "DENY" is Floodlight firewall "DROP"
        rule["action"] = "DROP" if action == "DENY" else action

    if "activityid" in param:
        rule["ruleid"] = activityid_to_ruleid(param["activityid"])

    if "switchid" in param:
        rule["any_dpid"] = False
        rule["dpid"] = openflow_utils.datapath_to_dpid(param["switchid"])

    if "src-inport" in param:
        rule["any_in_port"] = False
        rule["in_port"] = openflow_utils.portname_to_portnum(param["src-inport"])

    tmp = param.get("src-mac")
    if tmp:
        rule["any_dl_src"] = False
        rule["dl_src"] = tmp

    tmp = param.get("dst-mac")
    if tmp:
        rule["any_dl_dst"] = False
        rule["dl_dst"] = tmp

    if "dl-type" in param:
        rule["any_dl_type"] = False
        rule["dl_type"] = _ETH_TYPE_ARP if re.match("arp$", param["dl-type"], re.IGNORECASE) else _ETH_TYPE_IPV4

    tmp = param.get("src-ip")
    if tmp:
        fields = tmp.split('/')
        rule["any_nw_src"] = False
        rule["nw_src_prefix"] = fields[0]
        rule["nw_src_maskbits"] = 32 if len(fields) < 2 else int(fields[1])
        rule["any_dl_type"] = False
        rule["dl_type"] = _ETH_TYPE_IPV4

    tmp = param.get("dst-ip")
    if tmp:
        fields = tmp.split('/')
        rule["any_nw_dst"] = False
        rule["nw_dst_prefix"] = fields[0]
        rule["nw_dst_maskbits"] = 32 if len(fields) < 2 else int(fields[1])
        rule["any_dl_type"] = False
        rule["dl_type"] = _ETH_TYPE_IPV4

    tmp = param.get("nw-proto")
    if tmp:
        rule["any_nw_proto"] = False
        rule["nw_proto"] = socket.getprotobyname(tmp)
        rule["any_dl_type"] = False
        rule["dl_type"] = _ETH_TYPE_IPV4

    if "priority" in param:
        rule["priority"] = int(param["priority"])

    tmp = param.get("tp-src")
    if tmp:
        rule["any_tp_src"] = False
        rule["tp_src"] = int(tmp)

    tmp = param.get("tp-dst")
    if tmp:
        rule["any_tp_dst"] = False
        rule["tp_dst"] = int(tmp)

    return rule


def _match_rules(firewall_out_rule1, firewall_out_rule2):
    match_keys = set(firewall_out_rule1.keys()) | set(firewall_out_rule2.keys())
    match_keys.discard("ruleid")
    match_keys.discard("priority")
    return all(_compare_key(firewall_out_rule1, firewall_out_rule2, k) for k in match_keys)


def find_ruleid(url, action, param):
    x = floodlight_rest.FloodlightRest(url=url)
    rules = x.get('firewall_rules')
    if "activityid" in param:
        target_ruleid = activityid_to_ruleid(param["activityid"])
        for r in rules:
            if r["ruleid"] == target_ruleid:
                return r["ruleid"]
    else:
        converted_rule = _params_to_firewall_out(action, param)
        for r in rules:
            if _match_rules(r, converted_rule):
                return r["ruleid"]

    return None


def add_rule(url, action, param):
    # Remove any pre-existing rule that is the OPPOSITE of the rule being added
    delete_rule(url, "DENY" if _normalize_action_name(action) == "ALLOW" else "ALLOW", param)

    x = floodlight_rest.FloodlightRest(url=url)
    rule = _params_to_firewall_in(action, param)
    result = x.post('firewall_rules', rule)
    result["success"] = result.get("status", None) == u'Rule added'
    # Floodlight is very inconsistent in its field naming.  In this one place they use 'rule-id' instead of 'ruleid'
    if "rule-id" in result:
        result["activityid"] = ruleid_to_activityid(int(result.pop("rule-id")))
    return result


def delete_rule(url, action, param):
    ruleid = find_ruleid(url, action, param)
    if ruleid:
        x = floodlight_rest.FloodlightRest(url=url)
        result = x.delete('firewall_rules', {"ruleid": ruleid})
        result["success"] = result.get("status", None) == u'Rule deleted'
    else:
        result = {"success": False, "status": u"Rule not found"}

    return result


def list_rules(url):
    x = floodlight_rest.FloodlightRest(url=url)
    rules = x.get('firewall_rules')
    rules_out = [_firewall_out_to_params(rule) for rule in rules]
    return None if rules_out is None else {"firewall_rules": rules_out}


def get_firewall_status(url):
    x = floodlight_rest.FloodlightRest(url=url)
    result = x.get('firewall_status')
    result["enabled"] = result.get("result", None) == u'firewall enabled'
    return result


def enable_firewall(url):
    x = floodlight_rest.FloodlightRest(url=url)
    result = x.put('firewall_enable', None)
    result["success"] = result.get("status", None) == u'success'
    return result


def disable_firewall(url):
    x = floodlight_rest.FloodlightRest(url=url)
    result = x.put('firewall_disable', None)
    result["success"] = result.get("status", None) == u'success'
    return result


if __name__ == '__main__':
    import argparse
    from inspect import currentframe, getframeinfo
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true', help='run in pudb')
    parser.add_argument("url", nargs="?", default="http://127.0.0.1:8080", help="url of the Floodlight controller")
    args = parser.parse_args()
    if args.debug:
        import pudb
        pudb.set_trace()

    def _test_failed(msg, lineno):
        print('TEST FAILED at line {}: '.format(lineno), msg)

    url = args.url
    failcnt = 0

    result = list_rules(url)
    if not isinstance(result.get("firewall_rules"), list):
        _test_failed(result, getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    # Delete all pre-existing rules so we know the controller's state
    for r in result["firewall_rules"]:
        result = delete_rule(url, None, r)
        if not result["success"]:
            _test_failed(result, getframeinfo(currentframe()).lineno)
            failcnt = failcnt + 1

    result = add_rule(url, 'deny', {})
    if not result["success"]:
        _test_failed(result, getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    result = list_rules(url)
    if not isinstance(result.get("firewall_rules"), list):
        _test_failed(result, getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    # Delete rule with ruleid from prior call
    result = delete_rule(url, None, result)
    if not result["success"]:
        _test_failed(result, getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    result = add_rule(url, 'allow', {"priority": 12, "dst-ip": "10.1.2.0/24"})
    if not result["success"]:
        _test_failed(result, getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    # Duplicate rule should fail to add.
    result = add_rule(url, 'allow', {"priority": 12, "dst-ip": "10.1.2.0/24"})
    if result["success"]:
        _test_failed(result, getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    result = delete_rule(url, 'allow', {})
    if result["success"]:
        _test_failed(result, getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    # Delete rule by searching for match. Priority does not have to match.
    result = delete_rule(url, 'allow', {"priority": 13, "dst-ip": "10.1.2.0/24"})
    if not result["success"]:
        _test_failed(result, getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    # Test all parameter names, allow
    result = add_rule(url, 'allow', {
                                     "switchid": "dpid:00-00-00-00-00-00-00-01",
                                     "src-inport": "local",
                                     "src-mac": "00:01:02:03:04:05",
                                     "dst-mac": "ff:ff:ff:ff:ff:ff",
                                     "dl-type": "IPv4",
                                     "src-ip": "12.34.56.78",
                                     "dst-ip": "12.00.00.00/16",
                                     "nw-proto": "UDP",
                                     "tp-src": 1111,
                                     "tp-dst": 80,
                                     "priority": 12
                                    })
    if not result["success"]:
        _test_failed(result, getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    # Test all parameter names, deny
    result = add_rule(url, 'deny', {
                                     "switchid": "dpid:00-00-00-00-00-00-00-01",
                                     "src-inport": "local",
                                     "src-mac": "00:01:02:03:04:05",
                                     "dst-mac": "ff:ff:ff:ff:ff:ff",
                                     "dl-type": "IPv4",
                                     "src-ip": "12.34.56.78",
                                     "dst-ip": "12.00.00.00/16",
                                     "nw-proto": "UDP",
                                     "tp-src": 1111,
                                     "tp-dst": 80,
                                     "priority": 12
                                    })
    if not result["success"]:
        _test_failed(result, getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    result = enable_firewall(url)
    if not result["success"]:
        _test_failed(result, getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    result = get_firewall_status(url)
    if not result["enabled"]:
        _test_failed(result, getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    result = disable_firewall(url)
    if not result["success"]:
        _test_failed(result, getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    result = get_firewall_status(url)
    if result["enabled"]:
        _test_failed(result, getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if failcnt < 1:
        print("ALL TESTS PASSED")
    else:
        print("{} TESTS FAILED".format(failcnt))
