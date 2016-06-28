'''
Floodlight Firewall REST API
Created on February 26, 2016

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

import requests

GET = frozenset(['get'])
PUT = frozenset(['put'])
POST = frozenset(['post'])
DELETE = frozenset(['delete'])
SUPPORTED_METHODS = GET | PUT | POST | DELETE


class FloodlightFunction(object):
    '''
    Describes a single URN supported by Floodlight.
    The URN may support any combination of GET, POST, PUT, or DELETE functions.
    '''

    json_headers = {"Content-Type": "application/json"}

    def __init__(self, name, urn, **kwargs):
        '''
        Constructs a :class: FloodlightFunction

        :param name: A descriptive name for this function
        :param urn: The path to be used to reach the function via HTTP or HTTPS.  The urn may contain '{}' markers for parameters to be passed within HTTP requests
        :param methods: a set containing one or more of the strings 'get', 'put', 'post', and 'delete' (default is 'get')
        :param use_json: If true, then the Content-Type HTTP header will specify "application/json" and JSON-formatted data is expected
        :param path_params: An array of parameter names to be expected on every subsequent HTTP request.  The parameters (in order) replace '{}' markers in the urn.
        :return: :class: `FloodlightFunction` object
        :rtype rest.FloodlightFunction
        '''

        kwargs.setdefault('methods', frozenset(['get']))
        kwargs.setdefault('use_json', True)

        unsupported = kwargs['methods'] - SUPPORTED_METHODS
        if len(unsupported) > 0:
            raise TypeError('FloodlightFunction does not support method(s): {}'.format([x for x in unsupported]))

        self.name = name
        self.urn = urn
        self.methods = kwargs['methods']
        self.use_json = kwargs['use_json']

        if 'path_params' in kwargs:
            self.path_params = kwargs['path_params']
        else:
            self.path_params = None

    def format_uri(self, url, **kwargs):
        if not self.path_params:
            return url + self.urn
        else:
            return url + self.urn.format(*[kwargs[name] for name in self.path_params])

    def get(self, url, params=None, **kwargs):
        if 'get' not in self.methods:
            raise TypeError('{} does not support GET methods.'.format(self.name))

        if self.use_json:
            r = requests.get(self.format_uri(url, **kwargs), params=params, headers=self.json_headers)
        else:
            r = requests.get(self.format_uri(url, **kwargs), params=params)

        if r is None:
            return None

        r.raise_for_status()

        if self.use_json:
            return r.json()
        else:
            return r.text

    def post(self, url, data, params=None, **kwargs):
        if 'post' not in self.methods:
            raise TypeError('{} does not support POST methods.'.format(self.name))

        if self.use_json:
            r = requests.post(self.format_uri(url, **kwargs), json=data, params=params, headers=FloodlightFunction.json_headers)
        else:
            r = requests.post(self.format_uri(url, **kwargs), data=data, params=params)

        if r is None:
            return None

        r.raise_for_status()

        if self.use_json:
            return r.json()
        else:
            return r.text

    def put(self, url, data, params=None, **kwargs):
        if 'put' not in self.methods:
            raise TypeError('{} does not support PUT methods.'.format(self.name))

        if self.use_json:
            r = requests.put(self.format_uri(url, **kwargs), json=data, params=params, headers=FloodlightFunction.json_headers)
        else:
            r = requests.put(self.format_uri(url, **kwargs), data=data, params=params)

        if r is None:
            return None

        r.raise_for_status()

        if self.use_json:
            return r.json()
        else:
            return r.text

    def delete(self, url, data=None, params=None, **kwargs):
        if 'delete' not in self.methods:
            raise TypeError('{} does not support DELETE methods.'.format(self.name))

        if self.use_json:
            r = requests.delete(self.format_uri(url, **kwargs), json=data, params=params, headers=FloodlightFunction.json_headers)
        else:
            r = requests.delete(self.format_uri(url, **kwargs), data=data, params=params)

        if r is None:
            return None

        r.raise_for_status()

        if self.use_json:
            return r.json()
        else:
            return r.text


class FloodlightRest(object):
    '''
    classdocs
    '''

    functions = [
            # Controller API
            FloodlightFunction('switches', '/wm/core/controller/switches/json', methods=GET),
            FloodlightFunction('summary', '/wm/core/controller/summary/json', methods=GET),
            FloodlightFunction('modules', '/wm/core/module/all/json', methods=GET),
            FloodlightFunction('loaded_modules', '/wm/core/module/loaded/json', methods=GET),
            FloodlightFunction('counter', '/wm/core/counter/{}/{}/json', path_params=['module_name', 'counter_title'], methods=GET),
            FloodlightFunction('memory', '/wm/core/memory/json', methods=GET),
            FloodlightFunction('health', '/wm/core/health/json', methods=GET),
            FloodlightFunction('uptime', '/wm/core/system/uptime/json', methods=GET),
            FloodlightFunction('stored_tables', '/wm/core/storage/tables/json', methods=GET),

            # Role (Switch) API
            FloodlightFunction('switch_role', '/wm/core/switch/{}/role/json', path_params=['switch_id'], methods=GET | POST),

            # Multipart API
            FloodlightFunction('switch_stats', '/wm/core/switch/{}/{}/json', path_params=['switch_id', 'stat_type'], methods=GET),

            # Statistics API
            FloodlightFunction('enable_stat', '/wm/statistics/config/enable/json', methods=POST | PUT),
            FloodlightFunction('disable_stat', '/wm/statistics/config/disable/json', methods=POST | PUT),
            FloodlightFunction('bandwidth', '/wm/statistics/bandwidth/{}/{}/json', path_params=['switch_id', 'port_id'], methods=GET),

            # Topology API
            FloodlightFunction('clusters', '/wm/topology/switchclusters/json', methods=GET),
            FloodlightFunction('external_links', '/wm/topology/external-links/json', methods=GET),
            FloodlightFunction('links', '/wm/topology/links/json', methods=GET),
            FloodlightFunction('route', '/wm/topology/route/{}/{}/{}/{}/json', path_params=['src_dpid', 'src_port', 'dst_dpid', 'dst_port'], methods=GET),

            # Device APIs
            # Note: Device manager code does not appear to support arguments as of Floodlight 1.2
            FloodlightFunction('devices', '/wm/device/', methods=GET),

            # Static Flow Pusher API
            FloodlightFunction('config_static_flow', '/wm/staticflowpusher/json', methods=POST | DELETE),
            FloodlightFunction('list_static_flow', '/wm/staticflowpusher/list/{}/json', path_params=['switch_id'], methods=GET),
            FloodlightFunction('clear_static_flow', '/wm/staticflowpusher/clear/{}/json', path_params=['switch_id'], methods=GET),

            # Virtual Network Filter APIs
            FloodlightFunction('config_tenant_net', '/networkService/v1.1/tenants/{}/networks/{}', path_params=['tenant', 'network'],
                                methods=PUT | POST | DELETE),
            FloodlightFunction('config_tenant_host', '/networkService/v1.1/tenants/{}/networks/{}/ports/{}/attachment',
                                path_params=['tenant', 'network', 'port'], methods=PUT | DELETE),
            FloodlightFunction('list_tenants', '/networkService/v1.1/tenants/{}/networks', path_params=['tenant'], methods=GET),

            # Firewall API
            FloodlightFunction('firewall_status', '/wm/firewall/module/status/json', methods=GET),
            FloodlightFunction('firewall_enable', '/wm/firewall/module/enable/json', methods=PUT),
            FloodlightFunction('firewall_disable', '/wm/firewall/module/disable/json', methods=PUT),
            FloodlightFunction('firewall_subnet_mask', '/wm/firewall/module/subnet-mask/json', methods=GET | POST),
            FloodlightFunction('firewall_rules', '/wm/firewall/rules/json', methods=GET | POST | DELETE),

            # ACL API
            FloodlightFunction('acl_rules', '/wm/acl/rules/json', methods=GET | POST | DELETE),
            FloodlightFunction('acl_clear', '/wm/acl/clear/json', methods=GET, use_json=False)
        ]

    functions = {x.name: x for x in functions}

    statTypes = [
                  'aggregate', 'desc', 'flow',
                  'group', 'group-desc', 'group-features',
                  'meter', 'meter-config', 'meter-features',
                  'port', 'port-desc', 'queue',
                  'table', 'features'
                ]

    def __init__(self, **kwargs):
        '''
        Constructor
        '''
        kwargs.setdefault('url', 'http://127.0.0.1:8080')
        self.url = kwargs['url']

    def name(self):
        return self.url

    def get(self, name, **kwargs):
        if name in self.functions:
            funct = self.functions[name]
            return funct.get(self.url, **kwargs)
        else:
            raise NotImplementedError('No FloodlightFunction for operation name {}'.format(name))

    def put(self, name, data, **kwargs):
        if name in self.functions:
            funct = self.functions[name]
            return funct.put(self.url, data, **kwargs)
        else:
            raise NotImplementedError('No FloodlightFunction for operation name {}'.format(name))

    def post(self, name, data, **kwargs):
        if name in self.functions:
            funct = self.functions[name]
            return funct.post(self.url, data, **kwargs)
        else:
            raise NotImplementedError('No FloodlightFunction for operation name {}'.format(name))

    def delete(self, name, data, **kwargs):
        if name in self.functions:
            funct = self.functions[name]
            return funct.delete(self.url, data, **kwargs)
        else:
            raise NotImplementedError('No FloodlightFunction for operation name {}'.format(name))
