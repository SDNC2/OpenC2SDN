#!/usr/bin/python2.7
'''
Phantom App Connector for Floodlight SDN controller
Created on March 18, 2016

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
# import sys
# sys.path.extend(['/opt/phantom', '/opt/phantom/lib', '/opt/phantom/www'])

# Phantom App imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Imports local to this App
from oc2sdn_consts import *
import common.validators as validators

import simplejson as json
from datetime import datetime
from datetime import timedelta
import re


# Define the App Class
class FloodlightConnector(BaseConnector):

    def _action_unimplemented(self, url, param):
        return self.set_status(phantom.APP_ERROR, 'action not implemented.')

    def _test_connectivity(self, url, param):
        try:
            self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, url)
            # r = floodlight_rest.FloodlightRest(url=url)
            # r.get('health')
        except Exception as e:
            self.set_status(phantom.APP_ERROR, OC2SDN_ERR_SERVER_CONNECTION, e)
            self.append_to_message(OC2SDN_ERR_CONNECTIVITY_TEST)
            return self.get_status()

        return self.set_status_save_progress(phantom.APP_SUCCESS, OC2SDN_SUCC_CONNECTIVITY_TEST)

    def _unblock_flow(self, url, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        try:
            self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, url)
            # result = floodlight_firewall.add_rule(url, "allow", param)
            self.save_progress("done.")
            msg = result.get("status", OC2SDN_ERR_NO_STATUS)
            if msg == u'Rule added':
                action_result.add_data({"activityid": result["activityid"]})
                return action_result.set_status(phantom.APP_SUCCESS, msg)

            return action_result.set_status(phantom.APP_ERROR, msg)

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, OC2SDN_ERR_SERVER_CONNECTION, e)

    def _block_flow(self, url, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        try:
            self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, url)
            # result = floodlight_firewall.add_rule(url, "deny", param)
            self.save_progress("done.")
            msg = result.get("status", OC2SDN_ERR_NO_STATUS)
            if msg == u'Rule added':
                action_result.add_data({"activityid": result["activityid"]})
                return action_result.set_status(phantom.APP_SUCCESS, msg)

            return action_result.set_status(phantom.APP_ERROR, msg)

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, OC2SDN_ERR_SERVER_CONNECTION, e)

    def _block_address(self, url, param):
        if (validators.validate_ip4(param["ip_macaddress"]) or
                validators.validate_ip6(param["ip_macaddress"]) or
                validators.validate_cidr(param["ip_macaddress"])):
            outgoing_key = "dst-ip"
            incoming_key = "src-ip"
        elif validators.validate_mac(param["ip_macaddress"]):
            outgoing_key = "dst-mac"
            incoming_key = "src-mac"
        else:
            return self.set_status(phantom.APP_ERROR, OC2SDN_ERR_PARAM)

        incoming = {incoming_key: param["ip_macaddress"]}
        outgoing = {outgoing_key: param["ip_macaddress"]}

        if "priority" in param:
            incoming["priority"] = param["priority"]
            outgoing["priority"] = param["priority"]

        result1 = self._block_flow(url, incoming)
        result2 = self._block_flow(url, outgoing)

        return phantom.APP_SUCCESS if result1 and result2 else phantom.APP_ERROR

    def _unblock_address(self, url, param):
        if (validators.validate_ip4(param["ip_macaddress"]) or
                validators.validate_ip6(param["ip_macaddress"]) or
                validators.validate_cidr(param["ip_macaddress"])):
            outgoing_key = "dst-ip"
            incoming_key = "src-ip"
        elif validators.validate_mac(param["ip_macaddress"]):
            outgoing_key = "dst-mac"
            incoming_key = "src-mac"
        else:
            return self.set_status(phantom.APP_ERROR, OC2SDN_ERR_PARAM)

        incoming = {incoming_key: param["ip_macaddress"]}
        outgoing = {outgoing_key: param["ip_macaddress"]}

        if "priority" in param:
            incoming["priority"] = param["priority"]
            outgoing["priority"] = param["priority"]

        result1 = self._unblock_flow(url, incoming)
        result2 = self._unblock_flow(url, outgoing)

        return phantom.APP_SUCCESS if result1 and result2 else phantom.APP_ERROR

    def _block_arp(self, url, param):
        rule = {"dl-type": "ARP", "src-mac": param["macaddress"]}

        if "priority" in param:
            rule["priority"] = param["priority"]

        return self._block_flow(url, rule)

    def _unblock_arp(self, url, param):
        rule = {"dl-type": "ARP", "src-mac": param["macaddress"]}

        if "priority" in param:
            rule["priority"] = param["priority"]

        return self._unblock_flow(url, rule)

    def _list_static_flows(self, url, param):
        switch_id = param.get("switch_id", "all")
        print switch_id
        # return self._call_function_as_action(url,
        #                                     lambda: floodlight_sfp.list_static_flows(url=url, switch_id=switch_id), param=param)

    def _add_static_flow(self, url, param):
        if isinstance(param.get("match", None), basestring):
            param["match"] = json.loads(param["match"])

        if isinstance(param.get("instructions", None), basestring):
            param["instructions"] = json.loads(param["instructions"])

        # return self._call_function_as_action(url,
        #                                     lambda: floodlight_sfp.add_static_flow(url=url, param=param), param=param)

    def _delete_static_flow(self, url, param):
        # return self._call_function_as_action(url,
        #                                     lambda: floodlight_sfp.delete_static_flow(url=url, name=param["name"]), param=param)
        pass

    def _clear_static_flows(self, url, param):
        switch_id = param.get("switch_id", "all")
        print switch_id
        # return self._call_function_as_action(url,
        #                                     lambda: floodlight_sfp.clear_static_flows(url=url, switch_id=switch_id), param=param)
        pass

    def _enable_firewall(self, url, param):
        # return self._call_function_as_action(url, lambda: floodlight_firewall.enable_firewall(url))
        pass

    def _disable_firewall(self, url, param):
        # return self._call_function_as_action(url, lambda: floodlight_firewall.disable_firewall(url))
        pass

    def _get_firewall_status(self, url, param):
        # return self._call_function_as_action(url, lambda: floodlight_firewall.get_firewall_status(url))
        pass

    def _delete_firewall_rule(self, url, param):
        action_result = ActionResult(param)
        self.add_action_result(action_result)

        try:
            self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, url)
            # result = floodlight_firewall.delete_rule(url, None, param)
            self.save_progress("done.")
            if result is None:
                return action_result.set_status(phantom.APP_ERROR, OC2SDN_ERR_NO_DATA)

            action_result.add_data(result)
            if result.get("success") is not True:
                return action_result.set_status(phantom.APP_ERROR, result.get("status"))

            return action_result.set_status(phantom.APP_SUCCESS, OC2SDN_SUCC)

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, OC2SDN_ERR_SERVER_CONNECTION, e)

    def _list_firewall_rules(self, url, param):
        # return self._call_function_as_action(url, lambda: floodlight_firewall.list_rules(url))
        pass

    def _list_internal_links(self, url, param):
        action_result = ActionResult(param)
        self.add_action_result(action_result)

        try:
            self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, url)
            # link_list = floodlight_rest.FloodlightRest(url=url).get('links')
            self.save_progress("done.")
            if link_list is None:
                return action_result.set_status(phantom.APP_ERROR, OC2SDN_ERR_NO_DATA)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, OC2SDN_ERR_SERVER_CONNECTION, e)

        result = {"links": link_list, "success": True}
        # Add "dpid" namespaces to src-switch and dst-switch.
        for link in link_list:
            link["src-switch"] = "dpid:{}".format(link["src-switch"])
            link["dst-switch"] = "dpid:{}".format(link["dst-switch"])

        action_result.add_data(result)

        return action_result.set_status(phantom.APP_SUCCESS, OC2SDN_SUCC)

    def _list_external_links(self, url, param):
        action_result = ActionResult(param)
        self.add_action_result(action_result)

        try:
            self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, url)
            # link_list = floodlight_rest.FloodlightRest(url=url).get('external_links')
            self.save_progress("done.")
            if link_list is None:
                return action_result.set_status(phantom.APP_ERROR, OC2SDN_ERR_NO_DATA)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, OC2SDN_ERR_SERVER_CONNECTION, e)

        result = {"links": link_list, "success": True}
        # Add "dpid" namespaces to src-switch and dst-switch.
        for link in link_list:
            link["src-switch"] = "dpid:{}".format(link["src-switch"])
            link["dst-switch"] = "dpid:{}".format(link["dst-switch"])

        action_result.add_data(result)

        return action_result.set_status(phantom.APP_SUCCESS, OC2SDN_SUCC)

    def _list_switches(self, url, param):
        action_result = ActionResult(param)
        self.add_action_result(action_result)

        try:
            self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, url)
            # switch_list = floodlight_rest.FloodlightRest(url=url).get('switches')
            self.save_progress("done.")
            if switch_list is None:
                return action_result.set_status(phantom.APP_ERROR, OC2SDN_ERR_NO_DATA)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, OC2SDN_ERR_SERVER_CONNECTION, e)

        # Rearrange into a table-friendly format here.
        # This should definitely change if we ever get a "tree" render type
        result = {"switches": [], "success": True}
        for switch in switch_list:
            addrmatch = re.match("/([^:]+):([0-9]+)", switch["inetAddress"])
            if not addrmatch:
                return action_result.set_status(phantom.APP_ERROR, OC2SDN_ERR_PARSE, switch["inetAddress"])

            result["switches"].append(
                                {
                                 "ip": addrmatch.group(1),
                                 "port": addrmatch.group(2),
                                 "connectedSince": datetime.fromtimestamp(int(switch["connectedSince"]) / 1000).strftime('%Y-%m-%d %H:%M:%S'),
                                 "switchDPID": "dpid:{}".format(switch["switchDPID"])
                                })

        action_result.add_data(result)

        return action_result.set_status(phantom.APP_SUCCESS, OC2SDN_SUCC)

    def _get_uptime(self, url, param):
        action_result = ActionResult(param)
        self.add_action_result(action_result)

        try:
            self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, url)
            # result = floodlight_rest.FloodlightRest(url=url).get("uptime")
            self.save_progress("done.")
            if result is None:
                return action_result.set_status(phantom.APP_ERROR, OC2SDN_ERR_NO_DATA)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, OC2SDN_ERR_SERVER_CONNECTION, e)

        # Add a human-readable timestamp
        uptime = datetime.utcfromtimestamp(0) + timedelta(microseconds=int(result["systemUptimeMsec"]) * 1000)
        result["hhmmss"] = uptime.strftime('%H:%M:%S.%f')[:-3]
        result["success"] = True

        action_result.add_data(result)

        return action_result.set_status(phantom.APP_SUCCESS, OC2SDN_SUCC)

    def _list_devices(self, url, param):
        action_result = ActionResult(param)
        self.add_action_result(action_result)

        try:
            self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, url)
            # device_list = floodlight_rest.FloodlightRest(url=url).get('devices')
            self.save_progress("done.")
            if device_list is None:
                return action_result.set_status(phantom.APP_ERROR, OC2SDN_ERR_NO_DATA)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, OC2SDN_ERR_SERVER_CONNECTION, e)

        # Floodlight v1.2 and earlier returns a list.  Later versions return a root object containing a list.
        if isinstance(device_list, dict):
            device_list = device_list["devices"]

        # Rearrange into a table-friendly format here.
        # This should definitely change if we ever get a "tree" render type
        result = {"devices": [], "success": True}
        for device in device_list:
            for mac in device["mac"]:
                for vlan in device["vlan"]:
                    for ap in device["attachmentPoint"]:
                        for ip4 in device["ipv4"]:
                            result["devices"].append(
                                {"mac": mac,
                                 "vlan": vlan,
                                 "ip": ip4,
                                 "lastSeen": datetime.utcfromtimestamp(int(device["lastSeen"]) / 1000)
                                                                             .strftime('%Y-%m-%d %H:%M:%S UTC'),
                                 "attachmentPoint": {"port": ap["port"], "switchDPID": "dpid:{}".format(ap["switchDPID"])}
                                 })
                        for ip6 in device["ipv6"]:
                            result["devices"].append(
                                {"mac": mac,
                                 "vlan": vlan,
                                 "ip": ip6,
                                 "lastSeen": datetime.utcfromtimestamp(int(device["lastSeen"]) / 1000)
                                                                             .strftime('%Y-%m-%d %H:%M:%S UTC'),
                                 "attachmentPoint": {"port": ap["port"], "switchDPID": "dpid:{}".format(ap["switchDPID"])}
                                 })

        action_result.add_data(result)

        return action_result.set_status(phantom.APP_SUCCESS, OC2SDN_SUCC)

    def _call_function_as_action(self, url, funct, param={}):
        action_result = ActionResult(param)
        self.add_action_result(action_result)

        try:
            self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, url)
            result = funct()
            self.save_progress("done.")
            if result is None:
                return action_result.set_status(phantom.APP_ERROR, OC2SDN_ERR_NO_DATA)

            action_result.add_data(result)
            return action_result.set_status(phantom.APP_SUCCESS, OC2SDN_SUCC)

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, OC2SDN_ERR_SERVER_CONNECTION, e)

    _ACTION_ID_MAP = {
                     phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY: _test_connectivity,
                     "block_ip": _block_address,
                     "unblock_ip": _unblock_address,
                     "block_mac": _block_address,
                     "unblock_mac": _unblock_address,
                     "block_subnet": _block_address,
                     "unblock_subnet": _unblock_address,
                     "block_arp": _block_arp,
                     "unblock_arp": _unblock_arp,
                     "unblock_flow": _unblock_flow,
                     "block_flow": _block_flow,
                     "get_firewall_status": _get_firewall_status,
                     "enable_firewall": _enable_firewall,
                     "disable_firewall": _disable_firewall,
                     "delete_firewall_rule": _delete_firewall_rule,
                     "list_firewall_rules": _list_firewall_rules,
                     "list_switches": _list_switches,
                     "list_internal_links": _list_internal_links,
                     "list_external_links": _list_external_links,
                     "list_devices": _list_devices,
                     "get_uptime": _get_uptime,
                     "list_static_flows": _list_static_flows,
                     "add_static_flow": _add_static_flow,
                     "delete_static_flow": _delete_static_flow,
                     "clear_static_flows": _clear_static_flows
                    }

    def initialize(self):
        self.set_validator("vlan", validators.validate_vlan_id)
        self.set_validator("mac address", validators.validate_mac)
        self.set_validator("cidr", validators.validate_cidr)
        self.set_validator("dpid", validators.validate_scoped_dpid)
        self.set_validator("sdn:dataport", validators.validate_dataport)
        self.set_validator("cybox:Address", validators.validate_cybox_address)
        self.set_validator("cybox:Socket_Address", validators.validate_cybox_socket_address)
        self.set_validator("cybox:Network_Connection", validators.validate_cybox_network_connection)
        self.set_validator("sdn:flow", validators.validate_flow)
        return phantom.APP_SUCCESS

    def handle_action(self, param):
        config = self.get_config()
        controller_url = config.get(OC2SDN_CONTROLLER_URL)

        if (not controller_url):
            return self.set_status(phantom.APP_ERROR, 'controller url not set')

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()
        self.debug_print("action_id", self.get_action_identifier())

        funct = self._ACTION_ID_MAP.get(action_id, FloodlightConnector._action_unimplemented)
        return funct.__get__(self)(controller_url, param)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', action='store_true', help='run in pudb')
    parser.add_argument('jsonfile', help='json file describing action to take')
    args = parser.parse_args()
    if args.d:
        import pudb
        pudb.set_trace()

    with open(args.jsonfile) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = FloodlightConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
