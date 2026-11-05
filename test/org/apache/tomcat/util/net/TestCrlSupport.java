/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.tomcat.util.net;

import java.io.File;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.SSLException;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;

/*
 * Except with the APR/native connector (which uses PEM files), the server key
 * is loaded from a Java key store. With OpenSSL, the CRL must be applied
 * whether the server key is held in PEM files or in a Java key store.
 */
@RunWith(Parameterized.class)
public class TestCrlSupport extends TomcatBaseTest {

    @Parameters(name = "{0} with OpenSSL trust {2}, revoked cert {4}, CRL {5}")
    public static Collection<Object[]> parameters() {
        List<Object[]> parameterSets = new ArrayList<>();
        for (Boolean clientCertificateIsRevoked : booleans) {
            for (Boolean crlIsPopulated : booleans) {
                parameterSets.add(new Object[] { "JSSE", Boolean.FALSE, Boolean.FALSE,
                        "org.apache.tomcat.util.net.jsse.JSSEImplementation", clientCertificateIsRevoked, crlIsPopulated});
                parameterSets.add(new Object[] { "OpenSSL", Boolean.TRUE, Boolean.TRUE,
                        "org.apache.tomcat.util.net.openssl.OpenSSLImplementation", clientCertificateIsRevoked, crlIsPopulated });
                parameterSets.add(new Object[] { "OpenSSL", Boolean.TRUE, Boolean.FALSE,
                        "org.apache.tomcat.util.net.openssl.OpenSSLImplementation", clientCertificateIsRevoked, crlIsPopulated });
            }
        }

        return parameterSets;
    }

    @Parameter(0)
    public String connectorName;

    @Parameter(1)
    public boolean useOpenSSL;

    @Parameter(2)
    public boolean useOpenSSLTrust;

    @Parameter(3)
    public String sslImplementationName;

    @Parameter(4)
    public boolean clientCertificateIsRevoked;

    @Parameter(5)
    public boolean crlIsPopulated;


    @Override
    public void setUp() throws Exception {
        super.setUp();
        Tomcat tomcat = getTomcatInstance();
        TesterSupport.configureSSLImplementation(tomcat, sslImplementationName, useOpenSSL);
        TesterSupport.configureClientCertContext(tomcat, useOpenSSLTrust, TesterSupport.CLIENT_JKS, TesterSupport.CLIENT_CRL_JKS);
        SSLHostConfig sslHostConfig = tomcat.getConnector().findSslHostConfigs()[0];
        // Request the client certificate in the initial handshake so the test
        // does not depend on renegotiation support
        sslHostConfig.setCertificateVerification("required");
        // Configure the CRL
        if (crlIsPopulated) {
            sslHostConfig.setCertificateRevocationListFile(
                    new File(TesterSupport.POPULATED_CRL).getAbsolutePath());
        } else {
            sslHostConfig.setCertificateRevocationListFile(
                    new File(TesterSupport.EMPTY_CRL).getAbsolutePath());
        }
    }


    @Test
    public void testCrlClient() throws Exception {
        if (clientCertificateIsRevoked) {
            TesterSupport.configureClientSsl(TesterSupport.CLIENT_CRL_JKS);
        } else {
            TesterSupport.configureClientSsl(TesterSupport.CLIENT_JKS);
        }

        getTomcatInstance().start();

        // Protected resource
        String body;
        try {
            ByteChunk res = getUrl("https://localhost:" + getPort() + "/protected");
            body = res.toString();
        } catch (SSLException | SocketException e) {
            // May be observed when client certificate is rejected
            body = "FAILED";
        }

        if (!clientCertificateIsRevoked || !crlIsPopulated) {
            Assert.assertEquals("OK-" + TesterSupport.ROLE, body);
        } else {
            Assert.assertFalse(body, body.startsWith("OK-"));
        }
    }
}
