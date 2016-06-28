'''
Static Flow Pusher REST API for Floodlight SDN controller
Created on March 21, 2016

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
import simplejson as json
import copy

import openflow_utils

_CLEAR_FLOW_STATUS_REGEX = re.compile("Deleted all flows")
_DELETE_FLOW_STATUS_REGEX = re.compile("Entry .* deleted$")
_ADD_FLOW_STATUS_REGEX = re.compile("Entry pushed$")


def _xlate_to_sfp_in(param):
    param = copy.deepcopy(param)
    param["switch"] = openflow_utils.datapath_to_dpid(param["switch"])

    # move the match fields into the top-level flow dict since that is what Floodlight expects.
    # yet another place where Floodlight's output API doesn't match its input API.
    match = param.pop("match", None)
    if match is not None:
        param.update(match)

    # move the instructions into the top-level flow dict since that is what Floodlight expects.
    # yet another place where Floodlight's output API doesn't match its input API.
    instructions = param.pop("instructions", None)
    if instructions is not None:
        param.update(instructions)

    return param


def _xlate_from_sfp_out(dpid, flow):
    # Input format:
    # {
    #  "flow_name1": { "outPort": "any", "outGroup": "any", "cookieMask": 0, "command": "ADD", ... },
    #  "flow_name2": { "outPort": "any", "outGroup": "any", "cookieMask": 0, "command": "ADD", ... },
    #   ...
    # }
    #
    # Output format:
    # [
    #   { "name": "flow_name1", "switch": "dpid:dpid_value", "outPort": "any", "outGroup": "any", ...},
    #   { "name": "flow_name2", "switch": "dpid:dpid_value", "outPort": "any", "outGroup": "any", ...},
    #   ...
    # ]

    flow = copy.deepcopy(flow)
    for (name, flowbody) in flow.items():
        # Put dpid and flow name inside the innermost dict so Phantom can make the innermost dict a table row.
        # Also, flatten "match" and "instructions" into strings so Phantom can render them in a since table cell each.
        flowbody["switch"] = "dpid:{}".format(dpid)
        flowbody["name"] = name
        flowbody["match"] = json.dumps(flowbody["match"])
        flowbody["instructions"] = json.dumps(flowbody["instructions"])
    # Strip outer dict keys and return an array since "name" is now inside the dict.
    return flow.values()


def list_static_flows(url, switch_id="all"):
    if switch_id != "all":
        switch_id = openflow_utils.datapath_to_dpid(switch_id)

    flows_out = []
    x = floodlight_rest.FloodlightRest(url=url)
    flowdict = x.get('list_static_flow', switch_id=switch_id)
    for (dpid, dpflows) in flowdict.items():
        for flow in dpflows:
            flows_out.extend(_xlate_from_sfp_out(dpid, flow))

    return {"flows": flows_out, "success": True}


def clear_static_flows(url, switch_id="all"):
    if switch_id != "all":
        switch_id = openflow_utils.datapath_to_dpid(switch_id)

    x = floodlight_rest.FloodlightRest(url=url)
    result = x.get('clear_static_flow', switch_id=switch_id)
    result["success"] = _CLEAR_FLOW_STATUS_REGEX.match(result.get("status", "")) is not None
    return result


def add_static_flow(url, param):
    flow = _xlate_to_sfp_in(param)
    x = floodlight_rest.FloodlightRest(url=url)
    result = x.post('config_static_flow', flow)
    result["success"] = _ADD_FLOW_STATUS_REGEX.match(result.get("status", None)) is not None
    return result


def delete_static_flow(url, name):
    x = floodlight_rest.FloodlightRest(url=url)
    result = x.delete('config_static_flow', {"name": name})
    result["success"] = _DELETE_FLOW_STATUS_REGEX.match(result.get("status", "")) is not None
    return result


def _test_failed(msg, lineno):
    print(msg + ' at line {}'.format(lineno))


if __name__ == '__main__':
    import argparse
    from inspect import currentframe, getframeinfo

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', action='store_true', help='run in pudb')
    args = parser.parse_args()
    if args.d:
        import pudb
        pudb.set_trace()

    url = 'http://127.0.0.1:8080'
    failcnt = 0

    flows = [
             {
              "switch": "dpid:00:00:00:00:00:00:00:01",
              "name": "flow-ZERO",
              "cookie": "0",
              "priority": "32768",
              "match": {"in_port": "1"},
              "active": "true",
              "table": 4,
              "instructions": {"instruction_apply_actions": "output=2"}
             },
             {
              'switch': "dpid:00:00:00:00:00:00:00:01",
              "name": "flow_1",
              "cookie": "0",
              "priority": "32768",
              "match": {"in_port": "1"},
              "active": "true",
              "instructions": {"actions": "output=flood"}
             },
             {
              'switch': "dpid:00:00:00:00:00:00:00:02",
              "name": "flow_2",
              "cookie": "0",
              "priority": "32768",
              "match": {"in_port": "2"},
              "active": "true",
              "instructions": {"actions": "output=flood"}
             },
             {
              'switch': "dpid:00:00:00:00:00:00:00:03",
              "name": "flow_mod_3",
              "cookie": "0",
              "priority": "32768",
              "match": {"in_port": "1", "eth_type": "0x0806"},
              "active": "true",
              "instructions": {"instruction_apply_actions": "set_field=arp_tpa->10.0.0.2,output=2"}
             },
             {
              'switch': "dpid:00:00:00:00:00:00:00:03",
              "name": "flow_mod_4",
              "cookie": "0",
              "priority": "32768",
              "match": {"in_port": "1", "eth_type": "0x0806"},
              "active": "true",
              "instructions": {"actions": "set_field=arp_tpa->10.0.0.3,output=3"}
             },
             {
              'switch': "dpid:00:00:00:00:00:00:00:03",
              "name": "flow-ZERO",  # NOTE: duplicate name -- overwrites first flow-ZERO
              "cookie": "1234",
              "priority": "8000",
              "match": {"in_port": "1", "eth_type": "0x0800"},
              "active": "true",
              "instructions": {"actions": "output=local"}
             }
            ]

    result = clear_static_flows(url, "all")
    if not result["success"]:
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    result = list_static_flows(url, "all")
    if not result["success"] or len(result["flows"]) != 0:
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    try:
        result = add_static_flow(url, {})
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1
    except:
        # Empty dict should raise an exception. Test passed.
        pass

    for flow in flows:
        result = add_static_flow(url, flow)
        if not result["success"]:
            _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
            failcnt = failcnt + 1

    result = list_static_flows(url, "all")
    if not result["success"] or len(result["flows"]) != (len(flows) - 1):
        _test_failed("TEST FAILED (note: controller must be connected to dpids ::1, ::2 and ::3 for this to pass)", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    result = list_static_flows(url, "dpid:00:00:00:00:00:00:00:02")
    if not result["success"] or len(result["flows"]) != 1:
        _test_failed("TEST FAILED (note: controller must be connected to dpid ::2 for this to pass)", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    result = clear_static_flows(url, "dpid:00:00:00:00:00:00:00:02")
    if not result["success"]:
        _test_failed("TEST FAILED", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    result = list_static_flows(url, "dpid:00:00:00:00:00:00:00:02")
    if not result["success"] or len(result["flows"]) != 0:
        _test_failed("TEST FAILED (note: controller must be connected to dpid ::2 for this to pass)", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    result = delete_static_flow(url, "flow_1")
    if not result["success"]:
        _test_failed("TEST FAILED (note: controller must be connected to dpid ::1 for this to pass)", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    result = list_static_flows(url, "dpid:00:00:00:00:00:00:00:01")
    if not result["success"] or len(result["flows"]) != 0:
        _test_failed("TEST FAILED (note: controller must be connected to dpid ::1 for this to pass)", getframeinfo(currentframe()).lineno)
        failcnt = failcnt + 1

    if failcnt < 1:
        print("ALL TESTS PASSED")
    else:
        print("{} TESTS FAILED".format(failcnt))
