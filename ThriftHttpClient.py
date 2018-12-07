from cStringIO import StringIO
from thrift.transport.TTransport import TTransportBase
import requests
from requests_kerberos import HTTPKerberosAuth, REQUIRED
from subprocess import Popen, PIPE
import logging

log = logging.getLogger(__name__)


class AnotherHttpClient(TTransportBase):
    def __init__(self, uri, service_name, client_principal, keytab_location):
        assert uri
        assert service_name
        assert client_principal
        assert keytab_location
        self.__uri = uri
        self.__service_name = service_name
        self.__wbuf = StringIO()
        self.__content = None
        self.__cookies = None
        self.__response = None
        self.__client_principal = client_principal
        self.__keytab = keytab_location
        self.__kerb_auth = HTTPKerberosAuth(hostname_override=service_name, mutual_authentication=REQUIRED,
                                            force_preemptive=False, principal=client_principal)

    def isOpen(self):
        return True

    def open(self):
        TTransportBase.open(self)

    def close(self):
        TTransportBase.close(self)

    def read(self, sz):
        chunk = self.__content[:sz]
        self.__content = self.__content[sz:]
        return chunk

    def readAll(self, sz):
        return TTransportBase.readAll(self, sz)

    def write(self, buf):
        self.__wbuf.write(buf)

    def flush(self):
        self.check_and_kinit()
        # Pull data out of buffer
        data = self.__wbuf.getvalue()
        self.__wbuf = StringIO()
        headers = {
                   'Host' : self.__service_name,
                   'Content-Type' : 'application/x-thrift',
                   'Content-Length' : str(len(data))
                   }
        self.__response = requests.post(url=self.__uri, data=data, headers=headers,
                                        cookies=self.__cookies, auth=self.__kerb_auth)
        self.__content = self.__response.content
        if self.__response and self.__response.cookies and self.__response.cookies.__len__() > 0:
            self.__cookies = self.__response.cookies

    # checks if TGT for client_principal is present in credential cache
    def tgt_present(self):
        p = Popen('klist', stdout=PIPE, stderr=PIPE)
        out = p.stdout.read()
        return out and self.__client_principal in out

    def check_and_kinit(self):
        if self.tgt_present():
            return True
        log.debug('TGT not present in credential cache. Doing kinit.')
        cmd = ['kinit', '-kt', self.__keytab, self.__client_principal]
        p = Popen(cmd, stdout=PIPE, stderr=PIPE)
        err = p.stderr.read()
        if err:
            log.error('kinit failed with error.\n' + err)
            raise RuntimeError(err)
