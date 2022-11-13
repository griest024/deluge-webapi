import logging

import deluge.configmanager
from deluge import component
from deluge.common import get_version
from deluge.core.rpcserver import export
from deluge.plugins.pluginbase import CorePluginBase
from twisted.web import http, server
from packaging import version

LOGGER = logging.getLogger(__name__)

DEFAULT_PREFS = {
    'enable_cors': False,
    'allowed_origin': [],
}

# twisted uses byte strings in deluge version 2.1.0 onward
use_bytes = version.parse(get_version()) >= version.parse('2.1.0')

# Cookies don't get `SameSite=None` set correctly, we can hack it here
# see https://github.com/twisted/twisted/issues/10088
class ForceSecureSameSiteNoneCookieList(list):
    def append(self, cookie):
        list.append(self, cookie + b'; Secure; SameSite=None')

class Core(CorePluginBase):

    def enable(self):
        LOGGER.info('Enabling WebAPI plugin CORE ...')

        self.patched = False
        self.config = deluge.configmanager.ConfigManager('webapi.conf', DEFAULT_PREFS)

        if self.config['enable_cors']:
            self.patch_web_ui()

    def disable(self):
        LOGGER.info('Disabling WebAPI plugin CORE ...')

        self.config.save()

    @export
    def set_config(self, config):
        """sets the config dictionary"""

        for key in config.keys():
            self.config[key] = config[key]

        self.config.save()

        if self.config['enable_cors']:
            self.patch_web_ui()

        elif not self.config['enable_cors']:
            self.unpatch_web_ui()

    @export
    def get_config(self):
        return self.config.config

    def patch_web_ui(self):

        if self.patched:
            return

        LOGGER.info('Patching webui for CORS...')

        cmp_json = component.get('JSON')
        cmp_auth = component.get('Auth')

        # JSON
        self.old_render = cmp_json.render
        self.old_send_request = cmp_json._send_response
        cmp_json.render = self.render_patch
        cmp_json._send_response = self._send_response_patch

        # Auth
        self.old__create_session = cmp_auth._create_session
        cmp_auth._create_session = self._create_session_patch
        self.old_check_request = cmp_auth.check_request
        cmp_auth.check_request = self.check_request_patch

        self.patched = True

    def unpatch_web_ui(self):

        if not self.patched:
            return

        LOGGER.info('Unpatching webui for CORS...')

        cmp_json = component.get('JSON')
        cmp_auth = component.get('Auth')

        # JSON
        cmp_json.render = self.old_render
        cmp_json._send_response = self.old_send_request
        # Auth
        cmp_json._create_session = self.old__create_session
        cmp_json.check_request = self.old_check_request

        self.patched = False

    def check_request_patch(self, request, method=None, level=None):
        request.cookies = ForceSecureSameSiteNoneCookieList()

        result = self.old_check_request(request, method, level)

        return result

    def _create_session_patch(self, request, login='admin'):
        request.cookies = ForceSecureSameSiteNoneCookieList()

        result = self.old__create_session(request, login)

        return result

    def render_patch(self, request):

        if request.method != (b'OPTIONS' if use_bytes else 'OPTIONS'):
            return self.old_render(request)

        request.setResponseCode(http.OK)
        origin = request.getHeader('Origin')

        if origin in self.config['allowed_origin']:
            request.setHeader('Access-Control-Allow-Origin', origin)
            request.setHeader('Access-Control-Allow-Headers', 'content-type')
            request.setHeader('Access-Control-Allow-Methods', 'POST')
            request.setHeader('Access-Control-Allow-Credentials', 'true')

        request.write(b'' if use_bytes else '')
        request.finish()
        return server.NOT_DONE_YET

    def _send_response_patch(self, request, response):

        if request._disconnected:
            return ''

        origin = request.getHeader('Origin')

        if origin in self.config['allowed_origin']:
            request.setHeader('Access-Control-Allow-Origin', origin)
            request.setHeader('Access-Control-Allow-Credentials', 'true')

        return self.old_send_request(request, response)
