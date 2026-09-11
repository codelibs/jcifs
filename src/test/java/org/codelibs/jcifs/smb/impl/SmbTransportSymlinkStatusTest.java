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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HexFormat;
import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.context.BaseContext;
import org.codelibs.jcifs.smb.internal.smb2.Smb2Constants;
import org.codelibs.jcifs.smb.internal.smb2.create.Smb2CreateRequest;
import org.codelibs.jcifs.smb.internal.smb2.create.Smb2CreateResponse;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Pins how {@code SmbTransportImpl.checkStatus2} dispatches STATUS_STOPPED_ON_SYMLINK.
 *
 * The response is decoded from a real wire buffer rather than stubbed, so this also covers
 * {@code ServerMessageBlock2.readErrorResponse} populating the error data the dispatch relies on. A
 * response type that stopped treating this status as an error would fail here.
 */
class SmbTransportSymlinkStatusTest {

    /** A symbolic link error response for {@code link.txt -> target.txt}, as captured from Samba. */
    private static final String SYMLINK_ERROR_DATA =
            "44000000000000004000000053594d4c0c0000a0340000000000140014001400010000007400610072006700650074002e007400780074007400610072006700650074002e00740078007400";

    /** SMB2 CREATE, which ServerMessageBlock2 keeps protected. */
    private static final short SMB2_CREATE = 0x0005;

    private CIFSContext context;
    private SmbTransportImpl transport;

    @BeforeEach
    void setUp() throws Exception {
        this.context = new BaseContext(new PropertyConfiguration(new Properties()));
        this.transport = new SmbTransportImpl(this.context, null, 445, null, 0, false);
    }

    /**
     * Builds an SMB2 error response on the wire and decodes it, the way the transport would.
     *
     * @param status the NT status to report
     * @param errorContextCount the ErrorContextCount to report
     * @param errorData the ErrorData to carry, or null for none
     */
    private Smb2CreateResponse decodeErrorResponse(final int status, final int errorContextCount, final byte[] errorData) throws Exception {
        final int dataLength = errorData != null ? errorData.length : 0;
        final byte[] buffer = new byte[Smb2Constants.SMB2_HEADER_LENGTH + 8 + dataLength];

        System.arraycopy(SMBUtil.SMB2_HEADER, 0, buffer, 0, SMBUtil.SMB2_HEADER.length);
        SMBUtil.writeInt4(status, buffer, 8);
        SMBUtil.writeInt2(SMB2_CREATE, buffer, 12);

        int index = Smb2Constants.SMB2_HEADER_LENGTH;
        SMBUtil.writeInt2(9, buffer, index); // StructureSize
        buffer[index + 2] = (byte) errorContextCount;
        SMBUtil.writeInt4(dataLength, buffer, index + 4);
        index += 8;
        if (errorData != null) {
            System.arraycopy(errorData, 0, buffer, index, dataLength);
        }

        final Smb2CreateResponse response = new Smb2CreateResponse(this.context.getConfig(), "link.txt");
        response.setCommand(SMB2_CREATE);
        response.decode(buffer, 0);
        return response;
    }

    private Smb2CreateRequest request() {
        final Smb2CreateRequest request = new Smb2CreateRequest(this.context.getConfig(), "\\link.txt");
        request.setFullUNCPath(null, null, "\\\\server\\share\\link.txt");
        return request;
    }

    @Test
    @DisplayName("Turns STATUS_STOPPED_ON_SYMLINK into an SmbSymlinkException naming the target")
    void testDispatchesSymlinkStatus() throws Exception {
        final Smb2CreateResponse response =
                decodeErrorResponse(NtStatus.NT_STATUS_STOPPED_ON_SYMLINK, 1, HexFormat.of().parseHex(SYMLINK_ERROR_DATA));

        // the dispatch depends on readErrorResponse having captured the payload
        assertEquals(1, response.getErrorContextCount());
        assertEquals(NtStatus.NT_STATUS_STOPPED_ON_SYMLINK, response.getStatus());

        final Smb2CreateRequest request = request();
        final SmbSymlinkException e = assertThrows(SmbSymlinkException.class, () -> this.transport.checkStatus2(request, response));
        assertEquals("target.txt", e.getSubstituteName());
        assertTrue(e.isRelative());
        assertEquals("\\\\server\\share\\link.txt", e.getPath());
        assertEquals(NtStatus.NT_STATUS_STOPPED_ON_SYMLINK, e.getNtStatus());
    }

    @Test
    @DisplayName("Falls back to a plain SmbException when the error data cannot be decoded")
    void testFallsBackOnUndecodableErrorData() throws Exception {
        final Smb2CreateResponse response =
                decodeErrorResponse(NtStatus.NT_STATUS_STOPPED_ON_SYMLINK, 1, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });

        final Smb2CreateRequest request = request();
        final SmbException e = assertThrows(SmbException.class, () -> this.transport.checkStatus2(request, response));
        assertFalse(e instanceof SmbSymlinkException, "undecodable data must not produce a fabricated target");
        assertEquals(NtStatus.NT_STATUS_STOPPED_ON_SYMLINK, e.getNtStatus());
    }

    @Test
    @DisplayName("Falls back to a plain SmbException when the response carries no error data at all")
    void testFallsBackOnAbsentErrorData() throws Exception {
        final Smb2CreateResponse response = decodeErrorResponse(NtStatus.NT_STATUS_STOPPED_ON_SYMLINK, 0, null);

        final Smb2CreateRequest request = request();
        final SmbException e = assertThrows(SmbException.class, () -> this.transport.checkStatus2(request, response));
        assertFalse(e instanceof SmbSymlinkException);
        assertEquals(NtStatus.NT_STATUS_STOPPED_ON_SYMLINK, e.getNtStatus());
    }
}
