#!/usr/bin/env python3

# Copyright 2018 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
import sys
sys.path.append(os.path.join(os.environ.get('MOJO_BUILD_DIR'), 'zaza'))
import zaza.utilities.cert # noqa


def write_cert(path, name, data):
    with os.fdopen(os.open(os.path.join(CERT_DIR, name),
                           os.O_WRONLY | os.O_CREAT, 0o600), 'wb') as f:
        f.write(data)


ISSUER_NAME = 'OSCI'
IP_PREFIX = '.'.join(os.environ.get('MOJO_GATEWAY').split('.')[:2])
CERT_DIR = os.environ.get('MOJO_LOCAL_DIR')

alt_names = []
# We need to restrain the number of SubjectAlternativeNames we attempt to put
# in the certificate.  There is a hard limit for what length the sum of all
# extensions in the certificate can have.
for c in range(0, 11 + 1):
    for d in range(0, 256):
        alt_names.append('{}.{}.{}'.format(IP_PREFIX, c, d))

(cakey, cacert) = zaza.utilities.cert.generate_cert(ISSUER_NAME,
                                                    generate_ca=True)
(key, cert) = zaza.utilities.cert.generate_cert('*.serverstack',
                                                alternative_names=alt_names,
                                                issuer_name=ISSUER_NAME,
                                                signing_key=cakey)

write_cert(CERT_DIR, 'cacert.pem', cacert)
write_cert(CERT_DIR, 'ca.key', cakey)
write_cert(CERT_DIR, 'cert.pem', cert)
write_cert(CERT_DIR, 'cert.key', key)
