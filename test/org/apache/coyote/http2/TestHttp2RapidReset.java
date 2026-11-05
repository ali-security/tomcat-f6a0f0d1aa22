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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.util.concurrent.TimeUnit;

import org.junit.Assert;
import org.junit.Test;

import org.apache.tomcat.util.compat.JrePlatform;

/**
 * Tests for the HTTP/2 "Rapid Reset" denial of service (CVE-2023-44487) where
 * a client repeatedly opens a stream and immediately cancels it with a
 * RST_STREAM frame. Each request still triggers server side processing but
 * never counts against the concurrent stream limit.
 */
public class TestHttp2RapidReset extends Http2TestBase {

    // Far more streams than the overhead protection should permit
    private static final int RESET_STREAM_COUNT = 100;
    private static final int FIRST_STREAM_ID = 3;
    private static final String GOAWAY_PREFIX = "0-Goaway-[";
    // Well below the keep-alive timeout configured by Http2TestBase
    private static final long CLOSE_TIMEOUT_MILLIS = 10000;


    @Test
    public void testRapidResetSeparateWrites() throws Exception {
        http2Connect();

        try {
            for (int i = 0; i < RESET_STREAM_COUNT; i++) {
                int streamId = FIRST_STREAM_ID + 2 * i;
                sendSimpleGetRequest(streamId);
                sendRst(streamId, Http2Error.CANCEL.getCode());
            }
        } catch (IOException ioe) {
            // The server closed the connection before the client finished
            // sending all the frames. This is expected.
        }

        validateConnectionClosedForOverhead();
    }


    @Test
    public void testRapidResetSingleWrite() throws Exception {
        http2Connect();

        // Send all the HEADERS / RST_STREAM pairs in a single write so the
        // server reads many of them in a single read
        ByteArrayOutputStream flood = new ByteArrayOutputStream();
        for (int i = 0; i < RESET_STREAM_COUNT; i++) {
            int streamId = FIRST_STREAM_ID + 2 * i;
            byte[] frameHeader = new byte[9];
            ByteBuffer headersPayload = ByteBuffer.allocate(128);
            buildSimpleGetRequest(frameHeader, headersPayload, null, streamId);
            flood.write(frameHeader);
            flood.write(headersPayload.array(), headersPayload.arrayOffset(), headersPayload.limit());
            flood.write(buildRst(streamId, Http2Error.CANCEL.getCode()));
        }

        try {
            os.write(flood.toByteArray());
            os.flush();
        } catch (IOException ioe) {
            // The server closed the connection before the client finished
            // sending all the frames. This is expected.
        }

        validateConnectionClosedForOverhead();
    }


    @Test
    public void testOccasionalResetAllowed() throws Exception {
        http2Connect();

        // A well-behaved client that occasionally cancels a request must not
        // have its connection closed
        int streamId = FIRST_STREAM_ID;
        for (int i = 0; i < 10; i++) {
            // Two requests that complete normally...
            sendEmptyGetRequest(streamId);
            readUntilEndOfStream(streamId);
            streamId += 2;
            sendEmptyGetRequest(streamId);
            readUntilEndOfStream(streamId);
            streamId += 2;
            // ... and one that the client cancels
            sendEmptyGetRequest(streamId);
            sendRst(streamId, Http2Error.CANCEL.getCode());
            streamId += 2;
        }

        // The connection must still be usable
        sendSimpleGetRequest(streamId);
        readUntilEndOfStream(streamId);
    }


    private void validateConnectionClosedForOverhead() throws Exception {
        long start = System.nanoTime();
        // Read (and ignore) any responses and resets for the streams the server
        // processed before it closed the connection
        for (int i = 0; i < 1000; i++) {
            output.clearTrace();
            try {
                parser.readFrame(true);
            } catch (SocketTimeoutException ste) {
                Assert.fail("Connection not closed down after rapid reset");
            } catch (IOException ioe) {
                // On some platforms (e.g. Windows) the TCP connection close may
                // be processed before the client gets a chance to read the
                // GOAWAY frame. Only accept that if the connection was closed
                // well before the keep-alive timeout would have closed it.
                long elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
                Assert.assertTrue("Connection closed after [" + elapsed +
                        "] ms without a GOAWAY frame: " + ioe,
                        JrePlatform.IS_WINDOWS && elapsed < CLOSE_TIMEOUT_MILLIS);
                return;
            }
            String trace = output.getTrace();
            if (trace.startsWith(GOAWAY_PREFIX)) {
                Assert.assertTrue(trace, trace.contains(
                        "]-[" + Http2Error.ENHANCE_YOUR_CALM.getCode() + "]-["));
                int lastStreamId = Integer.parseInt(
                        trace.substring(GOAWAY_PREFIX.length(), trace.indexOf(']')));
                // The server must stop processing new streams well before the
                // end of the flood
                Assert.assertTrue(trace, lastStreamId < FIRST_STREAM_ID + RESET_STREAM_COUNT);
                return;
            }
        }

        Assert.fail("Connection not closed down after rapid reset");
    }


    private void readUntilEndOfStream(int streamId) throws Exception {
        String endOfStream = "\n" + streamId + "-EndOfStream\n";
        for (int i = 0; i < 100; i++) {
            parser.readFrame(true);
            String trace = output.getTrace();
            Assert.assertFalse(trace, trace.contains(GOAWAY_PREFIX));
            if (("\n" + trace).contains(endOfStream)) {
                output.clearTrace();
                return;
            }
        }

        Assert.fail("No response received for stream [" + streamId + "]");
    }


    private static byte[] buildRst(int streamId, long errorCode) {
        byte[] rstFrame = new byte[13];
        // length is always 4
        rstFrame[2] = 0x04;
        rstFrame[3] = FrameType.RST.getIdByte();
        // no flags
        // Stream ID
        ByteUtil.set31Bits(rstFrame, 5, streamId);
        // Payload
        ByteUtil.setFourBytes(rstFrame, 9, errorCode);
        return rstFrame;
    }
}
