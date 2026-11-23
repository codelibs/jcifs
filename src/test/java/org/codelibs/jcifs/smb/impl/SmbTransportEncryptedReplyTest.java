/*
 * © 2026 CodeLibs, Inc.
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.codelibs.jcifs.smb.Address;
import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.Credentials;
import org.codelibs.jcifs.smb.internal.CommonServerMessageBlock;
import org.codelibs.jcifs.smb.internal.smb2.Smb2EchoRequest;
import org.codelibs.jcifs.smb.internal.smb2.Smb2EchoResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

/**
 * The reply to an encrypted request.
 *
 * <p>
 * An encrypted request is not signed, so the reply is authenticated by nothing but its own encryption. A reply that
 * arrives in the clear is therefore not authenticated at all, and must not be taken for the server's answer.
 * </p>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SmbTransportEncryptedReplyTest {

    private static final int STATUS_SUCCESS = 0;
    private static final int STATUS_USER_SESSION_DELETED = 0xC0000203;
    private static final int STATUS_NETWORK_SESSION_EXPIRED = 0xC000035C;
    private static final int STATUS_ACCESS_DENIED = 0xC0000022;

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

    @BeforeEach
    void setup() throws Exception {
        when(this.cifsContext.getConfig()).thenReturn(this.configuration);
        when(this.configuration.getMaximumBufferSize()).thenReturn(65536);
        when(this.cifsContext.getCredentials()).thenReturn(this.credentials);
        when(this.credentials.unwrap(CredentialsInternal.class)).thenReturn(this.credentialsInternal);
        when(this.credentialsInternal.clone()).thenReturn(this.credentialsInternal);
        when(this.cifsContext.getBufferCache()).thenReturn(new BufferCacheImpl(4, 131072));

        this.transport = new SmbTransportImpl(this.cifsContext, this.address, 445, null, 0, false);
        set("smb2", Boolean.TRUE);
    }

    private void set(final String name, final Object value) throws Exception {
        final Field field = SmbTransportImpl.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(this.transport, value);
    }

    /**
     * Lays out a cleartext ECHO reply with the given status the way the receive loop finds it: the session message
     * header and the SMB2 header already in the small buffer, the 4 byte body still on the stream.
     */
    private void arrive(final int status) throws Exception {
        arrive(status, new byte[] { 4, 0, 0, 0 });
    }

    private void arrive(final int status, final byte[] body) throws Exception {
        final byte[] sbuf = new byte[1024];
        final int size = 64 + body.length;
        sbuf[1] = (byte) (size >> 16);
        sbuf[2] = (byte) (size >> 8);
        sbuf[3] = (byte) size;
        sbuf[4] = (byte) 0xFE;
        sbuf[5] = 'S';
        sbuf[6] = 'M';
        sbuf[7] = 'B';
        sbuf[8] = 64; // header structure size
        for (int i = 0; i < 4; i++) {
            sbuf[4 + 8 + i] = (byte) (status >>> 8 * i);
        }
        sbuf[4 + 12] = 0x0D; // ECHO
        sbuf[4 + 14] = 1; // credits granted
        sbuf[4 + 16] = 1; // SERVER_TO_REDIR
        final Field buffer = SmbTransportImpl.class.getDeclaredField("sbuf");
        buffer.setAccessible(true);
        System.arraycopy(sbuf, 0, buffer.get(this.transport), 0, sbuf.length);
        set("in", new ByteArrayInputStream(body));
    }

    private void receive(final Smb2EchoResponse response) throws Throwable {
        final Method method = SmbTransportImpl.class.getDeclaredMethod("doRecvSMB2", CommonServerMessageBlock.class);
        method.setAccessible(true);
        try {
            method.invoke(this.transport, response);
        } catch (final InvocationTargetException e) {
            throw e.getCause();
        }
    }

    private Smb2EchoResponse response(final boolean encryptedReplyRequired) {
        final Smb2EchoResponse response = new Smb2EchoResponse(this.configuration);
        response.setEncryptedReplyRequired(encryptedReplyRequired);
        return response;
    }

    @Test
    @DisplayName("a reply in the clear to an encrypted request is refused")
    void clearReplyToEncryptedRequestIsRefused() throws Exception {
        arrive(STATUS_SUCCESS);

        final IOException e = assertThrows(IOException.class, () -> receive(response(true)));
        assertTrue(e.getMessage().contains("arrived in the clear"), e.getMessage());
    }

    @Test
    @DisplayName("an error reply in the clear to an encrypted request is refused as well")
    void clearErrorReplyToEncryptedRequestIsRefused() throws Exception {
        arrive(STATUS_ACCESS_DENIED);

        final IOException e = assertThrows(IOException.class, () -> receive(response(true)));
        assertTrue(e.getMessage().contains("arrived in the clear"), e.getMessage());
    }

    @Test
    @DisplayName("a reply in the clear to a request that was not encrypted is accepted as before")
    void clearReplyToPlainRequestIsAccepted() throws Throwable {
        arrive(STATUS_SUCCESS);
        final Smb2EchoResponse response = response(false);

        assertDoesNotThrow(() -> receive(response));
        assertFalse(response.isEncryptedReplyRequired());
    }

    @Test
    @DisplayName("a server that has lost the session may say so in the clear, which is what triggers re-authentication")
    void sessionLossStatusesStayAccepted() throws Throwable {
        for (final int status : new int[] { STATUS_USER_SESSION_DELETED, STATUS_NETWORK_SESSION_EXPIRED }) {
            // The ERROR response body: structure size 9, no context, no data.
            arrive(status, new byte[] { 9, 0, 0, 0, 0, 0, 0, 0, 0 });
            final Smb2EchoResponse response = response(true);

            assertDoesNotThrow(() -> receive(response), String.format("0x%08x", status));
        }
    }

    @Test
    @DisplayName("sending an encrypted request marks its response, an unencrypted one does not")
    void sendingMarksTheResponse() throws Exception {
        final Method mark = SmbTransportImpl.class.getDeclaredMethod("requireEncryptedReplies",
                org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest.class);
        mark.setAccessible(true);

        final Smb2EchoRequest encrypted = new Smb2EchoRequest(this.configuration);
        encrypted.setResponse(new Smb2EchoResponse(this.configuration));
        encrypted.setEncrypt(true);
        mark.invoke(null, encrypted);
        assertTrue(((Smb2EchoResponse) encrypted.getResponse()).isEncryptedReplyRequired());

        final Smb2EchoRequest plain = new Smb2EchoRequest(this.configuration);
        plain.setResponse(new Smb2EchoResponse(this.configuration));
        mark.invoke(null, plain);
        assertFalse(((Smb2EchoResponse) plain.getResponse()).isEncryptedReplyRequired());
    }
}
