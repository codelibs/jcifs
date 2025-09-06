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
package org.codelibs.jcifs.smb.internal.smb2.info;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.Decodable;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.dtyp.SecurityDescriptor;
import org.codelibs.jcifs.smb.internal.fscc.FileFsFullSizeInformation;
import org.codelibs.jcifs.smb.internal.fscc.FileFsSizeInformation;
import org.codelibs.jcifs.smb.internal.fscc.FileInformation;
import org.codelibs.jcifs.smb.internal.fscc.FileInternalInfo;
import org.codelibs.jcifs.smb.internal.fscc.FileSystemInformation;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Response;
import org.codelibs.jcifs.smb.internal.smb2.Smb2Constants;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;

/**
 * SMB2 Query Info response message. This response contains the requested file system,
 * file, or security information from the server.
 *
 * @author mbechler
 *
 */
public class Smb2QueryInfoResponse extends ServerMessageBlock2Response {

    /**
     * Protocol overhead size for SMB2 query info response
     */
    public static final int OVERHEAD = Smb2Constants.SMB2_HEADER_LENGTH + 8;

    private final byte expectInfoType;
    private final byte expectInfoClass;
    private Decodable info;

    /**
     * Constructs a SMB2 query info response with the specified configuration and expected information types
     *
     * @param config
     *            the configuration to use for this response
     * @param expectInfoType
     *            the expected information type in the response
     * @param expectInfoClass
     *            the expected information class in the response
     */
    public Smb2QueryInfoResponse(final Configuration config, final byte expectInfoType, final byte expectInfoClass) {
        super(config);
        this.expectInfoType = expectInfoType;
        this.expectInfoClass = expectInfoClass;
    }

    /**
     * Gets the information returned by the query
     *
     * @return the information
     */
    public Decodable getInfo() {
        return this.info;
    }

    /**
     * Gets the information returned by the query, cast to the specified class type
     *
     * @param <T>
     *            the type of information to return
     * @param clazz
     *            the class type to cast the information to
     * @return the information
     * @throws CIFSException
     *             if the information cannot be cast to the specified type
     */
    @SuppressWarnings("unchecked")
    public <T extends Decodable> T getInfo(final Class<T> clazz) throws CIFSException {
        if (!clazz.isAssignableFrom(this.info.getClass())) {
            throw new CIFSException("Incompatible file information class");
        }
        return (T) getInfo();
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
     * @see org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2#readBytesWireFormat(byte[], int)
     */
    @Override
    protected int readBytesWireFormat(final byte[] buffer, int bufferIndex) throws SMBProtocolDecodingException {
        final int start = bufferIndex;

        final int structureSize = SMBUtil.readInt2(buffer, bufferIndex);
        if (structureSize != 9) {
            throw new SMBProtocolDecodingException("Expected structureSize = 9");
        }

        final int bufferOffset = SMBUtil.readInt2(buffer, bufferIndex + 2) + getHeaderStart();
        bufferIndex += 4;
        final int bufferLength = SMBUtil.readInt4(buffer, bufferIndex);
        bufferIndex += 4;
        final Decodable i = createInformation(this.expectInfoType, this.expectInfoClass);
        if (i != null) {
            i.decode(buffer, bufferOffset, bufferLength);
        }
        bufferIndex = Math.max(bufferIndex, bufferOffset + bufferLength);
        this.info = i;
        return bufferIndex - start;
    }

    private static Decodable createInformation(final byte infoType, final byte infoClass) throws SMBProtocolDecodingException {

        return switch (infoType) {
        case Smb2Constants.SMB2_0_INFO_FILE -> createFileInformation(infoClass);
        case Smb2Constants.SMB2_0_INFO_FILESYSTEM -> createFilesystemInformation(infoClass);
        case Smb2Constants.SMB2_0_INFO_QUOTA -> createQuotaInformation(infoClass);
        case Smb2Constants.SMB2_0_INFO_SECURITY -> createSecurityInformation(infoClass);
        default -> throw new SMBProtocolDecodingException("Unknwon information type " + infoType);
        };
    }

    /**
     * @param infoClass
     * @return
     * @throws SMBProtocolDecodingException
     */
    private static Decodable createFilesystemInformation(final byte infoClass) throws SMBProtocolDecodingException {
        return switch (infoClass) {
        case FileSystemInformation.FS_FULL_SIZE_INFO -> new FileFsFullSizeInformation();
        case FileSystemInformation.FS_SIZE_INFO -> new FileFsSizeInformation();
        default -> throw new SMBProtocolDecodingException("Unknown filesystem info class " + infoClass);
        };
    }

    /**
     * @param infoClass
     * @return
     * @throws SMBProtocolDecodingException
     */
    private static Decodable createSecurityInformation(final byte infoClass) throws SMBProtocolDecodingException {
        return new SecurityDescriptor();
    }

    /**
     * @param infoClass
     * @return
     * @throws SMBProtocolDecodingException
     */
    private static Decodable createQuotaInformation(final byte infoClass) throws SMBProtocolDecodingException {
        switch (infoClass) {
        default:
            throw new SMBProtocolDecodingException("Unknown quota info class " + infoClass);
        }
    }

    /**
     * @param infoClass
     * @return
     * @throws SMBProtocolDecodingException
     */
    private static Decodable createFileInformation(final byte infoClass) throws SMBProtocolDecodingException {
        return switch (infoClass) {
        case FileInformation.FILE_INTERNAL_INFO -> new FileInternalInfo();
        default -> throw new SMBProtocolDecodingException("Unknown file info class " + infoClass);
        };
    }

}
