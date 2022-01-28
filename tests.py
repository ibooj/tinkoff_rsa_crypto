import base64
from unittest import TestCase

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

from main import concat_values, calc_digest, calc_signature

KEY = """-----BEGIN PRIVATE KEY-----
MIIEugIBADANBgkqhkiG9w0BAQEFAASCBKQwggSgAgEAAoIBAQCIywyUKeK+1vMg
OeJlZXZIyjOEDb1DQpVDuT2qCPmfGeftj8GfP3nSPcxfanDxKpavMTH+LW0y5/5b
3BdbuvfgBe+hYNd1C7Jtg0quXCulRUZhcH3z7zbPksVjhr0gz0s1QgVcK6vOmSA2
jvJLNMrgnDa/Game31jVg+XBdcgfl6aKmXsTB/bOP7MZVMStUEpQQ3j0cRB/qJkJ
/qtLqgfE4tvn8bs/OFzHIBcZbkkNTcYZnM+leVyxfBRoh8WQr41vlK/NFS6UO5Qg
hlHjb4GVcVx5BZMF8ofz3O5bwBBVQol+u1/erslZn7AzMhCIO3M6K+RXmYpcF7Uo
QZDJvVVhAgMBAAECgf86Pjoc27iviNX74qmCgrDaTT2h/DeZa8AiFb0rqKagF2eo
voyyQVSdL7LU7X0pMfj2nvuqPa1A/4ZNlmhbpj/kIqLlE1apf1F5T218z8HFnLla
w4rdUf0EZHmm5regQKLFClc951o/nPMaR8LiQpgfCmRE+ag+/NnWD1LEDGIpEMk6
cAph/eG7e92URdcvcGKhW7IVRg9KLzC6/1o055PUbtfztNgbLNrc45FoYwwZmoJ6
TUTai7owiqTY/cPwYy1JNLkNWGrriayyHQ60r0TMa1iHPk8Y12E4DMfe1iFzuJC1
fkE2vldRhCoktReGp/9I2OA3AQTIf+dqeHJG43ECgYEAxiOQqDTsgLLJURMq7CxW
jROupxT793ZpWdmu1J8at7bz72yp6tYAOgnOYeb32t3DPoD210Ds0WZvgwyO2erB
Q5m3P1mrCbWIDyjE7prqPF7k/81a5ZyIhFxoJ67bFDWXH+taxVlDyPp5PykW12HA
+fKfUvuyarsMQoFgr/5DGX0CgYEAsL1ofGPnK5lt7ssfdyJfvRLomtFwEKq6mKL0
DDaGbNyWcXLxZNCDYhAfX/Mn221s6gwsb86sD2/+3fMkGsjNIq0KCtqYA12hrrHL
XKlrfss+hLhf51Psasod4LJ9pIwOA5M9daGbBOxnEYuUzJDCDWG/3F6IoU2gJVh+
jy+ukLUCgYBlmsFIcHNC/+uaZrDhEU+E4q3yQiF/Ybped/FeWQRzZx8qDNgJc5oE
KRkrPSymkIfZmnp6IXIPY28VjbAHcYmPp9i/ZLT/spZF58ss7EXnlWXrAxx0mFOt
RFGo39K6R0zq8l7GyqKnAkKAsAplglxaEB/Bhw6UCr0bsYqqVUGFZQKBgHmD0Int
miwU0kujJmAfpxl1Ha4MH3OmHqMBLrAS8Pt58onP0H5TCnHqydeLc7TfGEoW0pqQ
yyXWB7KMEB/GPZwAwu3Re0CdKKPWpA5ygXDsxnAz3+RJhDur+TzbG519mckFe/Ub
hlytOPQMNuMrB/Bxa5tU97WHjHsAzAsganIdAoGAe24+Cx/jAzL9PVv17eZIw1uf
E5nkjMDrs6f7kzAvcKVuwc/0MtgQj6nj5e1jwnDzpQMQclQzIXHUyJZ5eu5yqeGp
CggYIRuupVtoNDcnYaF8KKODTUDmD8072RU/11sBBbFxQqypyFq27r5XK1Q8+FZT
lfBGWTEKpGGHSQ9ERY4=
-----END PRIVATE KEY-----"""

CERT = """-----BEGIN CERTIFICATE-----
MIIDVTCCAj2gAwIBAgIEBXCRkTANBgkqhkiG9w0BAQsFADBbMQswCQYDVQQGEwI2
OTEOMAwGA1UECBMFU3RhdGUxDTALBgNVBAcTBENpdHkxEDAOBgNVBAoTB01haW5P
cmcxDDAKBgNVBAsTA09yZzENMAsGA1UEAxMETmFtZTAeFw0yMTA0MjExMzQxMjFa
Fw0yMjA0MjExMzQxMjFaMFsxCzAJBgNVBAYTAjY5MQ4wDAYDVQQIEwVTdGF0ZTEN
MAsGA1UEBxMEQ2l0eTEQMA4GA1UEChMHTWFpbk9yZzEMMAoGA1UECxMDT3JnMQ0w
CwYDVQQDEwROYW1lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiMsM
lCnivtbzIDniZWV2SMozhA29Q0KVQ7k9qgj5nxnn7Y/Bnz950j3MX2pw8SqWrzEx
/i1tMuf+W9wXW7r34AXvoWDXdQuybYNKrlwrpUVGYXB98+82z5LFY4a9IM9LNUIF
XCurzpkgNo7ySzTK4Jw2vxmpnt9Y1YPlwXXIH5emipl7Ewf2zj+zGVTErVBKUEN4
9HEQf6iZCf6rS6oHxOLb5/G7PzhcxyAXGW5JDU3GGZzPpXlcsXwUaIfFkK+Nb5Sv
zRUulDuUIIZR42+BlXFceQWTBfKH89zuW8AQVUKJfrtf3q7JWZ+wMzIQiDtzOivk
V5mKXBe1KEGQyb1VYQIDAQABoyEwHzAdBgNVHQ4EFgQUDi9YZ72rA17NZnwk/HZ/
BdaR4vYwDQYJKoZIhvcNAQELBQADggEBAHY7N6X8Unt0CgzQvWHR0hOR50bd0sds
gjxX+FLxt8TRg0iFR3ufIFpK8bNcew3gueUJtl7gxqT0t5rMP4w+Y7PBVJr6gClJ
hVj3+VZl/djjZ4rDsoZvTIIPspVwf5BHqMd9ezFHzRS8VrLknsuiy+AKiPkFYqWt
iag12g7/n7C01eJpPXqyO0g0d+YxANqYc9QJeIbUN8nCTKIKJ/A7lAb44/k/PwDY
jbI+kfCBEZHuFyKEl6Lt9Ivtg/owURi6skGWfIEsCdcjAwh5M/HtRWpt2Y1lfRPu
+7Umn5WbSvrU8l7D+UVtsdx5u4yjdE2ccCEerQxksTT2ivw7Vil+AqE=
-----END CERTIFICATE-----"""


class RsaCryptoTestCase(TestCase):
    def test_concat_values(self):
        data = {
            "C": "1",
            "A": "2",
            "B": "3"
        }
        concat_string = concat_values(data)
        self.assertEqual(concat_string, "231")

    def test_calc_digest(self):
        digest = calc_digest("NOTestCustomer3192.168.40.741573803282696E2C".encode('utf-8'))
        self.assertEqual(base64.b64encode(digest).decode('utf-8'), "03F2HA40d7eFJFHZh9QzTnbZ4g4sTATodlaGTyVI894=")

    def test_calc_signature(self):
        digest_bytes = "03F2HA40d7eFJFHZh9QzTnbZ4g4sTATodlaGTyVI894=".encode('utf-8')
        signature = calc_signature(KEY.encode('utf-8'), digest_bytes)

        # Check calculated signature value
        self.assertEqual(
            base64.b64encode(signature).decode('utf-8'),
            "Yaovdno+L3KXlNuTLyq11rC+vPIUvjHYRAb5xy+FAMKLxMOdbKVGQmTRDzUX/JAuf9aYe"
            "BAyxKOjBZ1Z3WPDudnCu9R7E/OqVlGssKlURgm0aSuul+Rj9VXdRwQDPcU9KL9zmzJDb9g"
            "P3TU6pgrMXrRGkcyPNFcT1Xjo24ZlFgCo+duYQ7f1U+qKp67KuWLHwRsfP14kqX84XB/0d"
            "PPMeKcPEBE+jYC3Mu+6jLUQvohEGz4a514NWLXmrWjL4BJbJj9VpFDYrH2N9hcm1OWxVvpD"
            "R32rANHS34AfWdAx2fYfKR0JHoyUqpYHCup3DBZT4VgvXnXEzdKzxcskzYbNHQ=="
        )

        cert = x509.load_pem_x509_certificate(CERT.encode('utf-8'))

        # Check signature verification
        # will raise an InvalidSignature exception if the signature isn’t valid.
        try:
            cert.public_key().verify(
                signature=signature,
                data=digest_bytes,
                algorithm=hashes.SHA256(),
                padding=PKCS1v15(),
            )
        except InvalidSignature:
            self.fail("Signature is not valid!")
