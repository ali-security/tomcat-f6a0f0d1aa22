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
package org.apache.tomcat.util.http.fileupload;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import org.apache.tomcat.util.http.fileupload.disk.DiskFileItemFactory;
import org.apache.tomcat.util.http.fileupload.impl.FileUploadIOException;
import org.apache.tomcat.util.http.fileupload.impl.SizeLimitExceededException;

/**
 * Verifies the configurable per part header size limit added for
 * CVE-2025-48976: the header section of each part may not exceed
 * {@link FileUploadBase#getPartHeaderSizeMax()} bytes (512 by default) rather
 * than the previous hard-coded 10kB.
 */
public class TestPartHeaderSizeLimit {

    private static final String BOUNDARY = "boundary1234";

    private static final String CRLF = "\r\n";

    /*
     * Builds a part whose header section (everything from the first header up
     * to and including the terminating CRLFCRLF) is exactly headerSize bytes.
     */
    private static void addPart(StringBuilder sb, String name, int headerSize) {
        sb.append("--").append(BOUNDARY).append(CRLF);
        int start = sb.length();
        sb.append("Content-Disposition: form-data; name=\"").append(name).append('\"');
        sb.append(CRLF);
        String padName = "X-Padding: ";
        int fixed = (sb.length() - start) + padName.length() + 4;
        Assert.assertTrue("Header size too small", headerSize >= fixed);
        sb.append(padName);
        for (int i = fixed; i < headerSize; i++) {
            sb.append('x');
        }
        sb.append(CRLF).append(CRLF);
        Assert.assertEquals(headerSize, sb.length() - start);
        sb.append("value-").append(name).append(CRLF);
    }

    private static byte[] buildMultipart(int... headerSizes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < headerSizes.length; i++) {
            addPart(sb, "field" + i, headerSizes[i]);
        }
        sb.append("--").append(BOUNDARY).append("--").append(CRLF);
        return sb.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    private static UploadContext newContext(final byte[] body) {
        return new UploadContext() {
            @Override
            public String getCharacterEncoding() {
                return StandardCharsets.ISO_8859_1.name();
            }

            @Override
            public String getContentType() {
                return "multipart/form-data; boundary=" + BOUNDARY;
            }

            @Override
            public InputStream getInputStream() {
                return new ByteArrayInputStream(body);
            }

            @Override
            public long contentLength() {
                return body.length;
            }
        };
    }

    private static FileUpload newUpload() {
        return new FileUpload(new DiskFileItemFactory());
    }

    private static void assertRejected(FileUpload upload, byte[] body, int limit) {
        try {
            upload.parseRequest(newContext(body));
            Assert.fail("Expected SizeLimitExceededException");
        } catch (SizeLimitExceededException e) {
            Assert.assertEquals(limit, e.getPermittedSize());
            // Header processing must stop as soon as the limit is exceeded
            Assert.assertEquals(limit + 1, e.getActualSize());
        } catch (FileUploadException e) {
            Assert.fail("Unexpected exception type: " + e);
        }
    }

    @Test
    public void testDefault() {
        Assert.assertEquals(512, FileUploadBase.DEFAULT_PART_HEADER_SIZE_MAX);
        Assert.assertEquals(512, newUpload().getPartHeaderSizeMax());
        MultipartStream ms = new MultipartStream(new ByteArrayInputStream(new byte[0]),
                BOUNDARY.getBytes(StandardCharsets.ISO_8859_1), null);
        Assert.assertEquals(512, ms.getPartHeaderSizeMax());
    }

    @Test
    public void testDefaultLimitAccepted() throws Exception {
        List<FileItem> items = newUpload().parseRequest(newContext(buildMultipart(512, 512)));
        Assert.assertEquals(2, items.size());
    }

    /*
     * Headers that were accepted by the old hard-coded 10kB limit but which
     * exceed the new default must be rejected.
     */
    @Test
    public void testDefaultLimitExceeded() {
        assertRejected(newUpload(), buildMultipart(513), 512);
    }

    @Test
    public void testDefaultLimitExceededOldLimit() {
        assertRejected(newUpload(), buildMultipart(8192), 512);
    }

    /*
     * Many parts with large headers - the attack described by CVE-2025-48976.
     */
    @Test
    public void testDefaultLimitManyLargeHeaders() {
        int[] headerSizes = new int[50];
        for (int i = 0; i < headerSizes.length; i++) {
            headerSizes[i] = 10000;
        }
        assertRejected(newUpload(), buildMultipart(headerSizes), 512);
    }

    /*
     * Only a later part has oversized headers.
     */
    @Test
    public void testDefaultLimitExceededLaterPart() {
        assertRejected(newUpload(), buildMultipart(100, 200, 600), 512);
    }

    /*
     * A header section that is never terminated must be rejected once the
     * limit is reached rather than being read until the end of the stream.
     */
    @Test
    public void testUnterminatedHeaders() {
        StringBuilder sb = new StringBuilder();
        sb.append("--").append(BOUNDARY).append(CRLF);
        sb.append("Content-Disposition: form-data; name=\"field\"").append(CRLF);
        sb.append("X-Padding: ");
        for (int i = 0; i < 100000; i++) {
            sb.append('x');
        }
        assertRejected(newUpload(), sb.toString().getBytes(StandardCharsets.ISO_8859_1), 512);
    }

    @Test
    public void testCustomLimit() throws Exception {
        FileUpload upload = newUpload();
        upload.setPartHeaderSizeMax(128);
        Assert.assertEquals(128, upload.getPartHeaderSizeMax());
        List<FileItem> items = upload.parseRequest(newContext(buildMultipart(128)));
        Assert.assertEquals(1, items.size());

        assertRejected(upload, buildMultipart(129), 128);
    }

    @Test
    public void testCustomLargerLimit() throws Exception {
        FileUpload upload = newUpload();
        upload.setPartHeaderSizeMax(2048);
        List<FileItem> items = upload.parseRequest(newContext(buildMultipart(2048, 1000)));
        Assert.assertEquals(2, items.size());

        assertRejected(upload, buildMultipart(1000, 2049), 2048);
    }

    @Test
    public void testNoLimit() throws Exception {
        FileUpload upload = newUpload();
        upload.setPartHeaderSizeMax(-1);
        List<FileItem> items = upload.parseRequest(newContext(buildMultipart(600, 20000)));
        Assert.assertEquals(2, items.size());
    }

    /*
     * The limit applies to direct users of MultipartStream.
     */
    @Test
    public void testMultipartStream() throws Exception {
        byte[] body = buildMultipart(300);

        MultipartStream ms = new MultipartStream(new ByteArrayInputStream(body),
                BOUNDARY.getBytes(StandardCharsets.ISO_8859_1), null);
        Assert.assertTrue(ms.skipPreamble());
        Assert.assertEquals(300, ms.readHeaders().length());

        ms = new MultipartStream(new ByteArrayInputStream(body),
                BOUNDARY.getBytes(StandardCharsets.ISO_8859_1), null);
        ms.setPartHeaderSizeMax(299);
        Assert.assertEquals(299, ms.getPartHeaderSizeMax());
        Assert.assertTrue(ms.skipPreamble());
        try {
            ms.readHeaders();
            Assert.fail("Expected FileUploadIOException");
        } catch (FileUploadIOException e) {
            Assert.assertTrue(e.getCause() instanceof SizeLimitExceededException);
            SizeLimitExceededException slee = (SizeLimitExceededException) e.getCause();
            Assert.assertEquals(299, slee.getPermittedSize());
            Assert.assertEquals(300, slee.getActualSize());
        }
    }
}
