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

import java.lang.reflect.Field;

import org.codelibs.jcifs.smb.Address;
import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.Credentials;
import org.codelibs.jcifs.smb.internal.smb2.io.Smb2ReadRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

/**
 * How many message ids a multi-credit request uses up.
 *
 * <p>
 * MS-SMB2 3.2.4.1.3 has a request consume one message id per credit it charges, not one per request. A client that
 * takes only one leaves the server expecting ids the client will never send, and the server stops answering once its
 * receive window has moved past them - so this is not cosmetic bookkeeping.
 * </p>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SmbTransportMultiCreditTest {

    private static final byte[] FILE_ID = new byte[16];

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
        when(this.cifsContext.getCredentials()).thenReturn(this.credentials);
        when(this.credentials.unwrap(CredentialsInternal.class)).thenReturn(this.credentialsInternal);
        when(this.credentialsInternal.clone()).thenReturn(this.credentialsInternal);
        this.transport = new SmbTransportImpl(this.cifsContext, this.address, 445, null, 0, false);
        // Message ids are only allocated this way on an SMB2 connection; SMB1 wraps them at 32000 instead.
        final Field smb2 = SmbTransportImpl.class.getDeclaredField("smb2");
        smb2.setAccessible(true);
        smb2.setBoolean(this.transport, true);
    }

    private Smb2ReadRequest read(final int creditCharge) {
        final Smb2ReadRequest request = new Smb2ReadRequest(this.configuration, FILE_ID, new byte[0], 0);
        request.setCreditCharge(creditCharge);
        return request;
    }

    @Test
    @DisplayName("a request consumes one message id per credit it charges")
    void multiCreditRequestConsumesItsRange() throws Exception {
        final long first = this.transport.makeKey(read(16));
        final long second = this.transport.makeKey(read(1));

        assertEquals(16, second - first, "a sixteen credit request owns sixteen message ids, so the next one starts past them");
    }

    @Test
    @DisplayName("a request that charges nothing still consumes one")
    void unchargedRequestConsumesOne() throws Exception {
        final long first = this.transport.makeKey(read(0));
        final long second = this.transport.makeKey(read(0));

        assertEquals(1, second - first, "a connection without multi-credit charges zero and must still advance by one");
    }
}
