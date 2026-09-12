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
package org.codelibs.jcifs.smb.internal.smb2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.mockito.Mockito.when;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.internal.smb2.io.Smb2ReadRequest;
import org.codelibs.jcifs.smb.internal.smb2.io.Smb2WriteRequest;
import org.codelibs.jcifs.smb.internal.smb2.nego.Smb2NegotiateRequest;
import org.codelibs.jcifs.smb.internal.smb2.nego.Smb2NegotiateResponse;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * What a payload larger than 64 KiB costs in credits.
 *
 * <p>
 * A read or write that spans more than 64 KiB is a multi-credit request: MS-SMB2 3.2.4.1.2 charges it one credit per
 * 64 KiB started, and a server that granted fewer rejects it. Charging one credit for a megabyte - which is what a
 * hardcoded cost does - is the difference between a transfer working and the connection being torn down.
 * </p>
 */
@DisplayName("SMB2 multi-credit accounting")
class Smb2MultiCreditTest {

    private static final byte[] FILE_ID = new byte[16];

    @Mock
    private Configuration mockConfig;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    /**
     * MS-SMB2 3.2.4.1.2: {@code (max(SendPayloadSize, ExpectedResponsePayloadSize) - 1) / 65536 + 1}.
     */
    @ParameterizedTest
    @CsvSource({ "1, 1", "65536, 1", "65537, 2", "131072, 2", "131073, 3", "1048576, 16" })
    @DisplayName("a read costs one credit per 64 KiB it spans")
    void readCreditCost(final int readLength, final int expectedCost) {
        final Smb2ReadRequest request = new Smb2ReadRequest(this.mockConfig, FILE_ID, new byte[0], 0);
        request.setReadLength(readLength);

        assertEquals(expectedCost, request.getCreditCost(),
                "a read of " + readLength + " bytes spans " + expectedCost + " credit(s) worth of payload");
    }

    @ParameterizedTest
    @CsvSource({ "1, 1", "65536, 1", "65537, 2", "131072, 2", "131073, 3", "1048576, 16" })
    @DisplayName("a write costs one credit per 64 KiB it spans")
    void writeCreditCost(final int dataLength, final int expectedCost) {
        final Smb2WriteRequest request = new Smb2WriteRequest(this.mockConfig, FILE_ID);
        request.setData(new byte[0], 0, dataLength);

        assertEquals(expectedCost, request.getCreditCost(),
                "a write of " + dataLength + " bytes spans " + expectedCost + " credit(s) worth of payload");
    }

    @Test
    @DisplayName("the charge reaches the wire at the offset the header reserves for it")
    void creditChargeIsEncoded() {
        final Smb2ReadRequest request = new Smb2ReadRequest(this.mockConfig, FILE_ID, new byte[0], 0);
        request.setCreditCharge(16);

        final byte[] buffer = new byte[256];
        request.encode(buffer, 0);

        assertEquals(16, SMBUtil.readInt2(buffer, 6), "CreditCharge sits at offset 6 of the SMB2 header");
    }

    /**
     * Multi-credit arrived with SMB 2.1. A server only grants it to a client that asked (MS-SMB2 3.3.5.4), so without
     * this the sizes stay at 64 KiB however much the server would have offered.
     */
    @ParameterizedTest
    @CsvSource({ "SMB202, false", "SMB210, true", "SMB300, true" })
    @DisplayName("LARGE_MTU is advertised from SMB 2.1 upwards")
    void negotiateAdvertisesLargeMtu(final DialectVersion maximumVersion, final boolean expected) {
        when(this.mockConfig.isDfsDisabled()).thenReturn(true);
        when(this.mockConfig.isEncryptionEnabled()).thenReturn(false);
        when(this.mockConfig.getMinimumVersion()).thenReturn(DialectVersion.SMB202);
        when(this.mockConfig.getMaximumVersion()).thenReturn(maximumVersion);
        // A client GUID only goes out from SMB 2.1, so only those dialects reach this at all.
        when(this.mockConfig.getMachineId()).thenReturn(new byte[16]);

        final Smb2NegotiateRequest request = new Smb2NegotiateRequest(this.mockConfig, 0);
        final boolean advertised = (request.getCapabilities() & Smb2Constants.SMB2_GLOBAL_CAP_LARGE_MTU) != 0;

        assertEquals(expected, advertised, "a client whose ceiling is " + maximumVersion
                + (expected ? " must ask for multi-credit" : " cannot use multi-credit and must not ask"));
    }

    @Test
    @DisplayName("the charge is only put on the wire once the server has granted multi-credit")
    void creditChargeIsStampedOnlyWhenNegotiated() {
        final Smb2ReadRequest withoutLargeMtu = new Smb2ReadRequest(this.mockConfig, FILE_ID, new byte[0], 0);
        withoutLargeMtu.setReadLength(1048576);
        negotiated(false).setupRequest(withoutLargeMtu);
        assertEquals(0, withoutLargeMtu.getCreditCharge(),
                "the field is reserved before SMB 2.1, so a connection without multi-credit must leave it zero");

        final Smb2ReadRequest withLargeMtu = new Smb2ReadRequest(this.mockConfig, FILE_ID, new byte[0], 0);
        withLargeMtu.setReadLength(1048576);
        negotiated(true).setupRequest(withLargeMtu);
        assertEquals(16, withLargeMtu.getCreditCharge(), "a megabyte read spans sixteen credits");
        assertNotEquals(0, withLargeMtu.getCreditCharge(), "a multi-credit request that ships a zero charge is rejected");
    }

    /**
     * A negotiate response that did or did not settle on multi-credit. Overriding the capability check keeps this
     * about {@code setupRequest} rather than about decoding a synthetic negotiate response.
     */
    private Smb2NegotiateResponse negotiated(final boolean largeMtu) {
        return new Smb2NegotiateResponse(this.mockConfig) {
            @Override
            public boolean haveCapabilitiy(final int cap) {
                return largeMtu && cap == Smb2Constants.SMB2_GLOBAL_CAP_LARGE_MTU;
            }
        };
    }
}
