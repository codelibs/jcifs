/*
 * © 2017 AgNO3 Gmbh & Co. KG
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
package org.codelibs.jcifs.smb.internal.smb2.session;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.impl.NtStatus;
import org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Response;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB2 Session Setup response message. This response contains the server's authentication
 * challenge or confirms successful session establishment.
 *
 * @author mbechler
 *
 */
public class Smb2SessionSetupResponse extends ServerMessageBlock2Response {

    /**
     * Session flag indicating this is a guest session
     */
    public static final int SMB2_SESSION_FLAGS_IS_GUEST = 0x1;

    /**
     * Session flag indicating this is a null/anonymous session
     */
    public static final int SMB2_SESSION_FLAGS_IS_NULL = 0x2;

    /**
     * Session flag indicating data encryption is required for this session
     */
    public static final int SMB2_SESSION_FLAG_ENCRYPT_DATA = 0x4;

    private int sessionFlags;
    private byte[] blob;

    /**
     * Constructs a SMB2 session setup response with the specified configuration
     *
     * @param config
     *            the configuration to use for this response
     */
    public Smb2SessionSetupResponse(final Configuration config) {
        super(config);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Response#prepare(org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest)
     */
    @Override
    public void prepare(final CommonServerMessageBlockRequest next) {
        if (isReceived()) {
            next.setSessionId(getSessionId());
        }
        super.prepare(next);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#isErrorResponseStatus()
     */
    @Override
    protected boolean isErrorResponseStatus() {
        return getStatus() != NtStatus.NT_STATUS_MORE_PROCESSING_REQUIRED && super.isErrorResponseStatus();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#writeBytesWireFormat(byte[], int)
     */
    @Override
    protected int writeBytesWireFormat(final byte[] dst, final int dstIndex) {
        return 0;
    }

    /**
     * {@inheritDoc}
     *
     * @throws SMBProtocolDecodingException
     *             if the response data is malformed
     *
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#readBytesWireFormat(byte[], int)
     */
    @Override
    protected int readBytesWireFormat(final byte[] buffer, int bufferIndex) throws SMBProtocolDecodingException {
        final int start = bufferIndex;

        final int structureSize = SMBUtil.readInt2(buffer, bufferIndex);
        if (structureSize != 9) {
            throw new SMBProtocolDecodingException("Structure size != 9");
        }

        this.sessionFlags = SMBUtil.readInt2(buffer, bufferIndex + 2);
        bufferIndex += 4;

        final int securityBufferOffset = SMBUtil.readInt2(buffer, bufferIndex);
        final int securityBufferLength = SMBUtil.readInt2(buffer, bufferIndex + 2);
        bufferIndex += 4;

        final int pad = bufferIndex - (getHeaderStart() + securityBufferOffset);
        this.blob = new byte[securityBufferLength];
        System.arraycopy(buffer, getHeaderStart() + securityBufferOffset, this.blob, 0, securityBufferLength);
        bufferIndex += pad;
        bufferIndex += securityBufferLength;

        return bufferIndex - start;
    }

    /**
     * Checks whether the session is either anonymous or a guest session
     *
     * @return whether the session is either anonymous or a guest session
     */
    public boolean isLoggedInAsGuest() {
        return (this.sessionFlags & (SMB2_SESSION_FLAGS_IS_GUEST | SMB2_SESSION_FLAGS_IS_NULL)) != 0;
    }

    /**
     * Gets the session flags from the response
     *
     * @return the sessionFlags
     */
    public int getSessionFlags() {
        return this.sessionFlags;
    }

    /**
     * Gets the security blob from the session setup response
     *
     * @return security blob
     */
    public byte[] getBlob() {
        return this.blob;
    }

}
