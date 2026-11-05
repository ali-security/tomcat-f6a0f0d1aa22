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
package org.apache.catalina.tribes.membership.cloud;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.tribes.util.StringManager;

/**
 * The Kubernetes cloud membership provider authenticates against the Kubernetes
 * API with the pod's service account token. That token is a credential and must
 * never be written to a log file nor embedded in an exception message.
 */
public class TestTokenStreamProvider {

    private static final String TOKEN = "S3cr3t-T0k3n-DoNotLog";

    private static final String MESSAGE_KEY = "tokenStream.failedConnection";


    /**
     * @return a URL on the loopback interface that is guaranteed not to be
     *             listening, so that connecting to it fails immediately
     */
    private static String unusedLoopbackUrl() throws IOException {
        int port;
        try (ServerSocket socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        return "http://127.0.0.1:" + port + "/";
    }


    /**
     * The token must not leak via the IOException used to report a failure to
     * reach the Kubernetes API.
     */
    @Test
    public void testTokenNotInFailedConnectionException() throws Exception {
        String url = unusedLoopbackUrl();
        TokenStreamProvider provider = new TokenStreamProvider(TOKEN, null);
        Map<String,String> headers = new HashMap<>();

        try {
            provider.openStream(url, headers, 1000, 1000);
            Assert.fail("Connection to [" + url + "] unexpectedly succeeded");
        } catch (IOException e) {
            // Guard against a vacuous pass: the token has to be in play for
            // this test to be able to detect a leak at all.
            Assert.assertEquals("Bearer " + TOKEN, headers.get("Authorization"));

            String message = e.getMessage();
            Assert.assertNotNull(message);
            // The message has to remain useful ...
            Assert.assertTrue(message, message.contains(url));
            // ... but must not include the token
            Assert.assertFalse(message, message.contains(TOKEN));

            // Nor may anything in the cause chain
            Throwable cause = e.getCause();
            Assert.assertNotNull(cause);
            while (cause != null) {
                String causeMessage = String.valueOf(cause.getMessage());
                Assert.assertFalse(causeMessage, causeMessage.contains(TOKEN));
                cause = cause.getCause();
            }
        }
    }


    /**
     * The message used to report the failure must not have a placeholder for
     * the token, else any additional argument passed by a caller would be
     * interpolated into it.
     */
    @Test
    public void testFailedConnectionMessageHasNoTokenPlaceholder() {
        // Locale.ROOT pins the lookup to LocalStrings.properties
        StringManager sm = StringManager.getManager(
                AbstractStreamProvider.class.getPackage().getName(), Locale.ROOT);

        String pattern = sm.getString(MESSAGE_KEY);
        Assert.assertNotNull(pattern);
        // The message takes the URL ...
        Assert.assertTrue(pattern, pattern.contains("{0}"));
        // ... and nothing else. This is the shape of the pre-fix message.
        Assert.assertFalse(pattern, pattern.contains("{1}"));

        String url = "http://127.0.0.1:1/";
        String message = sm.getString(MESSAGE_KEY, url, TOKEN);
        Assert.assertTrue(message, message.contains(url));
        Assert.assertFalse(message, message.contains(TOKEN));
    }


    /**
     * The request headers include the <code>Authorization</code> header that
     * carries the token, so they must not be written to the debug log.
     */
    @Test
    public void testTokenNotInConnectionDebugLog() throws Exception {
        final List<String> messages = new ArrayList<>();
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                messages.add(String.valueOf(record.getMessage()));
            }
            @Override
            public void flush() {
                // NO-OP
            }
            @Override
            public void close() {
                // NO-OP
            }
        };
        handler.setLevel(Level.ALL);

        Logger logger = Logger.getLogger(AbstractStreamProvider.class.getName());
        Level originalLevel = logger.getLevel();
        logger.addHandler(handler);
        logger.setLevel(Level.FINE);

        try {
            TokenStreamProvider provider = new TokenStreamProvider(TOKEN, null);
            Map<String,String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + TOKEN);

            // Opening the connection does not trigger any network traffic
            String url = unusedLoopbackUrl();
            URLConnection connection = provider.openConnection(url, headers, 1000, 1000);
            Assert.assertNotNull(connection);

            // Guard against a vacuous pass: debug logging has to be effective
            Assert.assertFalse("Nothing was logged at debug level", messages.isEmpty());

            boolean urlLogged = false;
            for (String message : messages) {
                Assert.assertFalse(message, message.contains(TOKEN));
                if (message.contains(url)) {
                    urlLogged = true;
                }
            }
            // The log entry has to remain useful
            Assert.assertTrue("The connection URL was not logged", urlLogged);
        } finally {
            logger.removeHandler(handler);
            logger.setLevel(originalLevel);
        }
    }
}
