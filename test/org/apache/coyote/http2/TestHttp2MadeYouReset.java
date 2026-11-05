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
import java.util.function.IntFunction;

import org.junit.Assert;
import org.junit.Test;

import org.apache.tomcat.util.compat.JrePlatform;

/**
 * Tests for the HTTP/2 "MadeYouReset" denial of service (CVE-2025-48989).
 * <p>
 * Rather than resetting streams itself (see {@link TestHttp2RapidReset}) the
 * client opens a stream and then sends a frame that is invalid for that stream
 * so that the <em>server</em> resets it. The request is still processed by the
 * server but, once reset, the stream no longer counts towards the concurrent
 * stream limit. Unless the resets sent by the server are counted as overhead,
 * the client can trigger an unlimited amount of server side processing.
 */
public class TestHttp2MadeYouReset extends Http2TestBase {

    // Far more streams than the overhead protection should permit
    private static final int STREAM_COUNT = 100;
    private static final int FIRST_STREAM_ID = 3;
    private static final String GOAWAY_PREFIX = "0-Goaway-[";
    // Well below the keep-alive timeout configured by Http2TestBase
    private static final long CLOSE_TIMEOUT_MILLIS = 10000;


    @Test
    public void testZeroWindowUpdateIncrement() throws Exception {
        http2Connect();

        // A WINDOW_UPDATE with an increment of zero is a stream error
        doTestMadeYouResetFlood(streamId -> buildWindowUpdate(streamId, 0));
    }


    @Test
    public void testWindowUpdateOverflow() throws Exception {
        http2Connect();

        // Increasing the stream flow control window beyond 2^31-1 is a stream
        // error
        doTestMadeYouResetFlood(streamId -> buildWindowUpdate(streamId, Integer.MAX_VALUE));
    }


    @Test
    public void testPrioritySelfDependency() throws Exception {
        http2Connect();

        // A stream that depends on itself is a stream error
        doTestMadeYouResetFlood(streamId -> buildPriority(streamId, streamId, 5));
    }


    @Test
    public void testHeaderCountLimit() throws Exception {
        // http2Connect() - modified
        enableHttp2();
        // Every request exceeds the header count limit so the server resets
        // every stream without the client having to send any other frames
        http2Protocol.setMaxHeaderCount(1);
        configureAndStartWebApplication();
        openClientConnection();
        doHttpUpgrade();
        sendClientPreface();
        validateHttp2InitialResponse();

        doTestMadeYouResetFlood(null);
    }


    @Test
    public void testPriorityInvalidLength() throws Exception {
        http2Connect();

        // A PRIORITY frame with a length other than 5 is a stream error. Wait
        // for each reset before sending the next request so that every invalid
        // frame is reported individually.
        for (int i = 0; i < STREAM_COUNT; i++) {
            int streamId = FIRST_STREAM_ID + 2 * i;
            try {
                writeRequest(streamId, buildPriority(streamId, 0, 4));
            } catch (IOException ioe) {
                // The server closed the connection before the client finished
                // sending the frames. This is expected.
                validateConnectionClosedForOverhead();
                return;
            }
            if (readUntilResetOrGoaway(streamId)) {
                return;
            }
        }

        Assert.fail("Connection not closed down after repeated server resets");
    }


    @Test
    public void testOccasionalServerResetAllowed() throws Exception {
        http2Connect();

        // Ensure the connection flow control window does not limit the number
        // of responses that can be received
        sendWindowUpdate(0, 1 << 30);

        // A well-behaved client that occasionally triggers a stream error must
        // not have its connection closed
        int streamId = FIRST_STREAM_ID;
        for (int i = 0; i < 10; i++) {
            // Three requests that complete normally...
            for (int j = 0; j < 3; j++) {
                sendSimpleGetRequest(streamId);
                readUntilEndOfStream(streamId);
                streamId += 2;
            }
            // ... and one that the server resets
            writeRequest(streamId, buildWindowUpdate(streamId, 0));
            Assert.assertFalse("Connection closed after an occasional stream error",
                    readUntilResetOrGoaway(streamId));
            streamId += 2;
        }

        // The connection must still be usable
        sendSimpleGetRequest(streamId);
        readUntilEndOfStream(streamId);
    }


    /*
     * Sends, in a single write, a simple GET request for each stream followed
     * (if a trigger is provided) by a frame that causes the server to reset
     * that stream.
     */
    private void doTestMadeYouResetFlood(IntFunction<byte[]> resetTrigger) throws Exception {
        ByteArrayOutputStream flood = new ByteArrayOutputStream();
        for (int i = 0; i < STREAM_COUNT; i++) {
            int streamId = FIRST_STREAM_ID + 2 * i;
            byte[] frameHeader = new byte[9];
            ByteBuffer headersPayload = ByteBuffer.allocate(128);
            buildSimpleGetRequest(frameHeader, headersPayload, null, streamId);
            flood.write(frameHeader);
            flood.write(headersPayload.array(), headersPayload.arrayOffset(), headersPayload.limit());
            if (resetTrigger != null) {
                flood.write(resetTrigger.apply(streamId));
            }
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


    /*
     * Sends a simple GET request for the given stream followed, in the same
     * write, by the given frame.
     */
    private void writeRequest(int streamId, byte[] resetTrigger) throws IOException {
        byte[] frameHeader = new byte[9];
        ByteBuffer headersPayload = ByteBuffer.allocate(128);
        buildSimpleGetRequest(frameHeader, headersPayload, null, streamId);
        ByteArrayOutputStream request = new ByteArrayOutputStream();
        request.write(frameHeader);
        request.write(headersPayload.array(), headersPayload.arrayOffset(), headersPayload.limit());
        request.write(resetTrigger);
        os.write(request.toByteArray());
        os.flush();
    }


    /*
     * Reads frames until either the server resets the given stream (returns
     * false) or the server closes the connection for excessive overhead
     * (returns true).
     */
    private boolean readUntilResetOrGoaway(int streamId) throws Exception {
        String reset = streamId + "-RST-[";
        for (int i = 0; i < 100; i++) {
            output.clearTrace();
            try {
                parser.readFrame(true);
            } catch (IOException ioe) {
                // The server closed the connection. Check for a GOAWAY.
                validateConnectionClosedForOverhead();
                return true;
            }
            String trace = output.getTrace();
            if (trace.startsWith(GOAWAY_PREFIX)) {
                validateGoaway(trace);
                return true;
            }
            if (trace.startsWith(reset)) {
                output.clearTrace();
                return false;
            }
        }

        Assert.fail("No reset received for stream [" + streamId + "]");
        return false;
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
                Assert.fail("Connection not closed down after repeated server resets");
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
                validateGoaway(trace);
                return;
            }
        }

        Assert.fail("Connection not closed down after repeated server resets");
    }


    private void validateGoaway(String trace) {
        Assert.assertTrue(trace, trace.contains(
                "]-[" + Http2Error.ENHANCE_YOUR_CALM.getCode() + "]-["));
        int lastStreamId = Integer.parseInt(
                trace.substring(GOAWAY_PREFIX.length(), trace.indexOf(']')));
        // The server must stop processing new streams well before the end of
        // the attack
        Assert.assertTrue(trace, lastStreamId < FIRST_STREAM_ID + STREAM_COUNT);
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


    private static byte[] buildWindowUpdate(int streamId, int increment) {
        byte[] updateFrame = new byte[13];
        // length is always 4
        updateFrame[2] = 0x04;
        updateFrame[3] = FrameType.WINDOW_UPDATE.getIdByte();
        // no flags
        // Stream ID
        ByteUtil.set31Bits(updateFrame, 5, streamId);
        // Payload
        ByteUtil.set31Bits(updateFrame, 9, increment);
        return updateFrame;
    }


    private static byte[] buildPriority(int streamId, int streamDependencyId, int length) {
        // A valid PRIORITY frame always has a length of 5
        byte[] priorityFrame = new byte[9 + length];
        // length
        ByteUtil.setThreeBytes(priorityFrame, 0, length);
        // type
        priorityFrame[3] = FrameType.PRIORITY.getIdByte();
        // No flags
        // Stream ID
        ByteUtil.set31Bits(priorityFrame, 5, streamId);
        // Payload (stream dependency and, for a valid frame, weight)
        ByteUtil.set31Bits(priorityFrame, 9, streamDependencyId);
        if (length > 4) {
            priorityFrame[13] = 15;
        }
        return priorityFrame;
    }
}
