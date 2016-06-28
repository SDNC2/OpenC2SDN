import json
import exceptions

from klein import Klein

def process_message(url, oc2_msg):
    try:
        action = oc2_msg["action"]
        target = oc2_msg["target"]
        modifiers = oc2_msg.get("modifiers")
        return { "action": action, "target": target, "modifiers": modifiers, "url": url}
    except:
        return {"success": False, "message": "Internal error."}
    

class OpenC2Proxy(object):

    app = Klein()

    def __init__(self, oc2_handler):
        self.handler = oc2_handler

    @app.route('/oc2', methods=['PUT', 'DELETE', 'GET'])
    def invalid_method(self, request):
        return json.dumps({'success': False, 'message': 'Only POST operations are allowed for this URL.'})

    @app.route('/oc2', methods=['POST'])
    def process_oc2_command(self, request):
        try:
            request.setHeader('Content-Type', 'application/json')
            body = json.loads(request.content.read())

            # PROCESS OPENC2 message here.
            result = self.handler(body)
            if isinstance(result, basestring):
                return result
            else:
                return json.dumps(result)

        except exceptions.ValueError:
                return json.dumps({'success': False, 'message': 'Failed to parse JSON-encoded action.'})

if __name__ == '__main__':
    import argparse
    from inspect import currentframe, getframeinfo
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true', help='run in pudb')
    parser.add_argument('-p', '--port', default=8123, type=int, help="server TCP port number")
    parser.add_argument('-u', '--url', default="http://127.0.0.1:8080", help="URL of Floodlight REST API")
    args = parser.parse_args()
    if args.debug:
        import pudb
        pudb.set_trace()

    server_address = ( '', args.port )
    url = args.url

    server = OpenC2Proxy(lambda msg: process_message(url, msg))
    server.app.run(*server_address)

