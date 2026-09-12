/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;

import org.codelibs.jcifs.smb.Address;
import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.Credentials;
import org.codelibs.jcifs.smb.internal.smb2.io.Smb2WriteRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

/**
 * The length the transport puts in front of a message.
 *
 * <p>
 * A direct TCP session message carries a 24 bit length (MS-SMB2 2.1). Masking it to 16 bits is invisible while every
 * message fits in 64 KiB and silently corrupts the stream the moment one does not: the server reads the wrong number
 * of bytes and every later message on the connection is parsed from the wrong offset.
 * </p>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SmbTransportFramingTest {

    /** A write of this much data encodes to exactly 65536 bytes: 64 header + 48 body + payload. */
    private static final int PAYLOAD_FOR_EXACTLY_64_KIB = 65536 - 64 - 48;

    @Mock
    private CIFSContext cifsContext;
    @Mock
    private Configuration configuration;
    @Mock
    private Credentials credentials;
    @Mock
    private CredentialsInternal credentialsInternal;
    @Mock
    private Address address;

    private SmbTransportImpl transport;
    private ByteArrayOutputStream written;

    @BeforeEach
    void setup() throws Exception {
        when(this.cifsContext.getConfig()).thenReturn(this.configuration);
        when(this.cifsContext.getCredentials()).thenReturn(this.credentials);
        when(this.credentials.unwrap(CredentialsInternal.class)).thenReturn(this.credentialsInternal);
        when(this.credentialsInternal.clone()).thenReturn(this.credentialsInternal);
        // Sized here rather than taken from the configuration, so this stays a test about framing even if the
        // maximum buffer size changes.
        when(this.cifsContext.getBufferCache()).thenReturn(new BufferCacheImpl(4, 131072));

        this.transport = new SmbTransportImpl(this.cifsContext, this.address, 445, null, 0, false);
        this.written = new ByteArrayOutputStream();
        set("out", this.written);
        set("smb2", Boolean.TRUE);
    }

    private void set(final String name, final Object value) throws Exception {
        final Field field = SmbTransportImpl.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(this.transport, value);
    }

    @Test
    @DisplayName("a message of exactly 64 KiB is framed with its real length")
    void framesSixtyFourKibibytesWithoutTruncating() throws Exception {
        final Smb2WriteRequest request = new Smb2WriteRequest(this.configuration, new byte[16]);
        request.setData(new byte[PAYLOAD_FOR_EXACTLY_64_KIB], 0, PAYLOAD_FOR_EXACTLY_64_KIB);

        this.transport.doSend(request);

        final byte[] frame = this.written.toByteArray();
        final int length = (frame[1] & 0xFF) << 16 | (frame[2] & 0xFF) << 8 | frame[3] & 0xFF;
        assertEquals(0, frame[0], "a session message starts with a zero type byte");
        assertEquals(65536, length, "the session message length is 24 bits wide, so 65536 must survive it intact");
    }
}
