![Imagination Technologies Limited logo](doc/img.png)

----

## DTLS.Net

[![License (3-Clause BSD)](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg?style=flat-square)](http://opensource.org/licenses/BSD-3-Clause)

DTLS.Net was developed for use in an [implementation](https://github.com/Creatordev/DeviceServer) of the Open Mobile Alliance's (OMA) Lightweight Machine to Machine protocol (LWM2M). For this reason it only supports the following cipher suites:

* TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
* TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
* TLS_PSK_WITH_AES_128_CCM_8
* TLS_PSK_WITH_AES_128_CBC_SHA256

### Limitations

Since the client is only required to serve for the above project it has several inherent limitations:

1. No automatic retransmission
2. No support for fragmentation of handshake packets
3. Does not verify Server Certificates (against CA)

The server currently also has the following limitations:

1. Does not verify client Certificates
2. No support for fragmentation of handshake packets

Hopefully over time these will be implemented, in the meantime we hope this is still useful.

----

### Contributing

We welcome all contributions to this project and we give credit where it's due. Anything from enhancing functionality to improving documentation and bug reporting - it's all good.

Find out more in the [contributor guide](CONTRIBUTING.md).

### Credits

We would like to thank all of our current [contributors](CONTRIBUTORS).


----

### License information

* All code and documentation developed by Imagination Technologies Limited is licensed under the [BSD 3-clause license](LICENSE).
* Bouncy Castle by The Legion of the Bouncy Castle is licensed under an [adaptation of the MIT X11 License](https://bouncycastle.org/csharp/licence.html).


----

