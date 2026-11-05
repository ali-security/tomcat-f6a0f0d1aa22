/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.coyote.http2;

import java.io.File;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.connector.Connector;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SSLHostConfigCertificate.Type;
import org.apache.tomcat.util.net.TesterSupport;

/**
 * Checks that the HTTP/2 <code>:authority</code> pseudo header is matched
 * against the SSLHostConfig selected by the TLS handshake (strict SNI).
 * <p>
 * The test client does not send SNI (single label host name) so the TLS
 * handshake always uses the default SSLHostConfig. Requests for a virtual host
 * with a different SSLHostConfig - that may, for example, require a client
 * certificate - must be rejected.
 */
public class TestHttp2Sni extends Http2TestBase {

    @Test
    public void testAuthorityUsesDefaultSslHostConfig() throws Exception {
        doTestAuthority("localhost", true, true);
    }


    @Test
    public void testAuthorityWithDifferentSslHostConfig() throws Exception {
        doTestAuthority("foobar", true, false);
    }


    /*
     * CVE-2026-32990: Host names are case insensitive so this is a request for
     * the virtual host [foobar] and must be rejected in the same way.
     */
    @Test
    public void testAuthorityWithDifferentSslHostConfigUpperCase() throws Exception {
        doTestAuthority("FOOBAR", true, false);
    }


    @Test
    public void testAuthorityWithDifferentSslHostConfigStrictSniDisabled() throws Exception {
        doTestAuthority("foobar", false, true);
    }


    private void doTestAuthority(String authority, boolean strictSni, boolean expectSuccess)
            throws Exception {
        enableHttp2(true);

        Connector connector = getTomcatInstance().getConnector();
        if (!strictSni) {
            Assert.assertTrue(connector.setProperty("strictSni", "false"));
        }

        // Add a dedicated SSLHostConfig for [foobar]
        SSLHostConfig sslHostConfig = new SSLHostConfig();
        SSLHostConfigCertificate certificate = new SSLHostConfigCertificate(sslHostConfig, Type.UNDEFINED);
        sslHostConfig.addCertificate(certificate);
        if (connector.getProtocolHandlerClassName().contains("Apr")) {
            certificate.setCertificateFile(new File(TesterSupport.LOCALHOST_RSA_CERT_PEM).getAbsolutePath());
            certificate.setCertificateKeyFile(new File(TesterSupport.LOCALHOST_RSA_KEY_PEM).getAbsolutePath());
        } else {
            certificate.setCertificateKeystoreFile(new File(TesterSupport.LOCALHOST_RSA_JKS).getAbsolutePath());
            certificate.setCertificateKeystorePassword(TesterSupport.JKS_PASS);
        }
        sslHostConfig.setHostName("foobar");
        connector.addSslHostConfig(sslHostConfig);

        configureAndStartWebApplication();
        openClientConnection(true);
        doHttpUpgrade();
        sendClientPreface();
        validateHttp2InitialResponse();

        byte[] frameHeader = new byte[9];
        ByteBuffer headersPayload = ByteBuffer.allocate(128);

        List<Header> headers = new ArrayList<>(4);
        headers.add(new Header(":method", "GET"));
        headers.add(new Header(":scheme", "https"));
        headers.add(new Header(":path", "/simple"));
        headers.add(new Header(":authority", authority + ":" + getPort()));

        buildGetRequest(frameHeader, headersPayload, null, headers, 3);
        writeFrame(frameHeader, headersPayload);

        if (expectSuccess) {
            readSimpleGetResponse();
            Assert.assertEquals(getSimpleResponseTrace(3), output.getTrace());
        } else {
            handleGoAwayResponse(1, Http2Error.COMPRESSION_ERROR);
        }
    }
}
