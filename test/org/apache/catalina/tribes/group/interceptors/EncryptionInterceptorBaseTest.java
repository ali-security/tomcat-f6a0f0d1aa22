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
package org.apache.catalina.tribes.group.interceptors;

import org.junit.Before;

import org.apache.catalina.tribes.ChannelException;
import org.apache.catalina.tribes.ChannelInterceptor;
import org.apache.catalina.tribes.ChannelMessage;
import org.apache.catalina.tribes.Member;
import org.apache.catalina.tribes.group.ChannelInterceptorBase;
import org.apache.catalina.tribes.group.InterceptorPayload;
import org.apache.catalina.tribes.io.ChannelData;
import org.apache.catalina.tribes.io.XByteBuffer;

public abstract class EncryptionInterceptorBaseTest {

    private static final String encryptionKey128 = "cafebabedeadbeefbeefcafecafebabe";

    protected EncryptInterceptor src;
    protected EncryptInterceptor dest;

    @Before
    public void setup() {
        src = new EncryptInterceptor();
        src.setEncryptionKey(encryptionKey128);

        dest = new EncryptInterceptor();
        dest.setEncryptionKey(encryptionKey128);

        src.setNext(new PipedInterceptor(dest));
        dest.setPrevious(new ValueCaptureInterceptor());
    }

    protected static String roundTrip(String input, EncryptInterceptor src, EncryptInterceptor dest) throws Exception {
        byte[] bytes = input.getBytes("UTF-8");

        bytes = roundTrip(bytes, src, dest);

        return new String(bytes, "UTF-8");
    }

    protected static byte[] roundTrip(byte[] input, EncryptInterceptor src, EncryptInterceptor dest) throws Exception {
        ChannelData msg = new ChannelData(false);
        msg.setMessage(new XByteBuffer(input, false));
        src.sendMessage(null, msg, null);

        return ((ValueCaptureInterceptor)dest.getPrevious()).getValue();
    }

    protected static class PipedInterceptor extends ChannelInterceptorBase {
        private ChannelInterceptor dest;

        public PipedInterceptor(ChannelInterceptor dest) {
            if(null == dest)
                throw new IllegalArgumentException("Destination must not be null");

            this.dest = dest;
        }

        @Override
        public void sendMessage(Member[] destination, ChannelMessage msg, InterceptorPayload payload)
                throws ChannelException {
            dest.messageReceived(msg);
        }
    }

    protected static class ValueCaptureInterceptor extends ChannelInterceptorBase {
        private byte[] value;

        @Override
        public void sendMessage(Member[] destination, ChannelMessage msg, InterceptorPayload payload)
                throws ChannelException {
            value = msg.getMessage().getBytes();
        }

        @Override
        public void messageReceived(ChannelMessage msg) {
            value = msg.getMessage().getBytes();
        }

        public byte[] getValue() {
            return value;
        }
    }
}
