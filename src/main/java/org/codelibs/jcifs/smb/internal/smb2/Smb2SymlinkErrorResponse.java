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

import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.codelibs.jcifs.smb.util.Strings;

/**
 * The SMB2_SYMLINK_ERROR_RESPONSE a server returns alongside STATUS_STOPPED_ON_SYMLINK, telling the
 * client where the link it refused to follow actually points.
 *
 * <p>
 * See MS-SMB2 2.2.2.2.1. Over SMB 3.1.1 the payload is wrapped in an SMB2 ERROR Context (MS-SMB2
 * 2.2.2.1); earlier dialects place the same structure directly in ErrorData. The response's
 * ErrorContextCount says which form arrived, so both are accepted here.
 * </p>
 */
public final class Smb2SymlinkErrorResponse {

    /** Marks the error data as a symbolic link error response ("SYML" in little endian). */
    public static final int SYMLINK_ERROR_TAG = 0x4C4D5953;

    /** The reparse point tag identifying a symbolic link (MS-FSCC 2.1.2.4). */
    public static final int IO_REPARSE_TAG_SYMLINK = 0xA000000C;

    /** SYMLINK_FLAG_RELATIVE: the substitute name is relative to the link's own directory. */
    private static final int SYMLINK_FLAG_RELATIVE = 0x1;

    /** Size of the SMB2 ERROR Context header that SMB 3.1.1 prepends. */
    private static final int ERROR_CONTEXT_HEADER_SIZE = 8;

    /** Size of the fixed part of SMB2_SYMLINK_ERROR_RESPONSE, up to but excluding PathBuffer. */
    private static final int FIXED_SIZE = 28;

    /**
     * Number of bytes ReparseDataLength covers before PathBuffer: the four name offset/length
     * fields plus Flags.
     */
    private static final int REPARSE_DATA_HEADER_SIZE = 12;

    private final int unparsedPathLength;
    private final boolean relative;
    private final String substituteName;
    private final String printName;

    private Smb2SymlinkErrorResponse(final int unparsedPathLength, final boolean relative, final String substituteName,
            final String printName) {
        this.unparsedPathLength = unparsedPathLength;
        this.relative = relative;
        this.substituteName = substituteName;
        this.printName = printName;
    }

    /**
     * Decodes the symbolic link error data carried by a STATUS_STOPPED_ON_SYMLINK response.
     *
     * @param errorData the raw ErrorData of the SMB2 error response
     * @param errorContextCount the response's ErrorContextCount; non-zero means the payload is
     *            wrapped in an SMB2 ERROR Context, as SMB 3.1.1 does
     * @return the decoded symbolic link error response
     * @throws SMBProtocolDecodingException if the data is absent, truncated, or not a symbolic link
     *             error response
     */
    public static Smb2SymlinkErrorResponse decode(final byte[] errorData, final int errorContextCount) throws SMBProtocolDecodingException {
        if (errorData == null) {
            throw new SMBProtocolDecodingException("Symlink error response carries no error data");
        }

        int bufferIndex = 0;
        if (errorContextCount > 0) {
            if (errorData.length < ERROR_CONTEXT_HEADER_SIZE) {
                throw new SMBProtocolDecodingException("Truncated SMB2 error context header: " + errorData.length + " bytes");
            }
            final int contextDataLength = SMBUtil.readInt4(errorData, 0);
            bufferIndex = ERROR_CONTEXT_HEADER_SIZE;
            if (contextDataLength < 0 || contextDataLength > errorData.length - bufferIndex) {
                throw new SMBProtocolDecodingException("SMB2 error context claims " + contextDataLength + " bytes but only "
                        + (errorData.length - bufferIndex) + " are present");
            }
        }

        final int available = errorData.length - bufferIndex;
        if (available < FIXED_SIZE) {
            throw new SMBProtocolDecodingException("Truncated symlink error response: " + available + " bytes");
        }

        final int symLinkLength = SMBUtil.readInt4(errorData, bufferIndex);
        final int symLinkErrorTag = SMBUtil.readInt4(errorData, bufferIndex + 4);
        final int reparseTag = SMBUtil.readInt4(errorData, bufferIndex + 8);

        if (symLinkErrorTag != SYMLINK_ERROR_TAG) {
            throw new SMBProtocolDecodingException(
                    "Not a symlink error response, SymLinkErrorTag is 0x" + Integer.toHexString(symLinkErrorTag));
        }
        if (reparseTag != IO_REPARSE_TAG_SYMLINK) {
            throw new SMBProtocolDecodingException("Unsupported reparse tag 0x" + Integer.toHexString(reparseTag));
        }
        // SymLinkLength covers everything from SymLinkErrorTag onwards
        if (symLinkLength < FIXED_SIZE - 4 || symLinkLength > available - 4) {
            throw new SMBProtocolDecodingException("Invalid SymLinkLength " + symLinkLength + " for " + available + " bytes");
        }

        final int reparseDataLength = SMBUtil.readInt2(errorData, bufferIndex + 12);
        final int unparsedPathLength = SMBUtil.readInt2(errorData, bufferIndex + 14);
        final int substituteNameOffset = SMBUtil.readInt2(errorData, bufferIndex + 16);
        final int substituteNameLength = SMBUtil.readInt2(errorData, bufferIndex + 18);
        final int printNameOffset = SMBUtil.readInt2(errorData, bufferIndex + 20);
        final int printNameLength = SMBUtil.readInt2(errorData, bufferIndex + 22);
        final int flags = SMBUtil.readInt4(errorData, bufferIndex + 24);

        // ReparseDataLength covers the name offset/length fields, Flags, and PathBuffer
        if (reparseDataLength < REPARSE_DATA_HEADER_SIZE) {
            throw new SMBProtocolDecodingException("Invalid ReparseDataLength " + reparseDataLength);
        }
        final int pathBufferIndex = bufferIndex + FIXED_SIZE;
        final int pathBufferLength = reparseDataLength - REPARSE_DATA_HEADER_SIZE;
        if (pathBufferLength > errorData.length - pathBufferIndex) {
            throw new SMBProtocolDecodingException("ReparseDataLength " + reparseDataLength + " overruns the error data");
        }
        if (unparsedPathLength % 2 != 0) {
            throw new SMBProtocolDecodingException("UnparsedPathLength " + unparsedPathLength + " is not a UTF-16 length");
        }

        checkName("SubstituteName", substituteNameOffset, substituteNameLength, pathBufferLength);
        checkName("PrintName", printNameOffset, printNameLength, pathBufferLength);

        return new Smb2SymlinkErrorResponse(unparsedPathLength, (flags & SYMLINK_FLAG_RELATIVE) == SYMLINK_FLAG_RELATIVE,
                Strings.fromUNIBytes(errorData, pathBufferIndex + substituteNameOffset, substituteNameLength),
                Strings.fromUNIBytes(errorData, pathBufferIndex + printNameOffset, printNameLength));
    }

    private static void checkName(final String what, final int offset, final int length, final int pathBufferLength)
            throws SMBProtocolDecodingException {
        if (offset < 0 || length < 0 || length % 2 != 0 || offset > pathBufferLength || length > pathBufferLength - offset) {
            throw new SMBProtocolDecodingException(
                    what + " at " + offset + " length " + length + " does not fit a " + pathBufferLength + " byte path buffer");
        }
    }

    /**
     * Returns the number of bytes at the end of the requested path that the server did not consume
     * before it hit the link, as a UTF-16 byte count. Resolving the link means replacing everything
     * before this tail.
     *
     * @return the unparsed path length in bytes
     */
    public int getUnparsedPathLength() {
        return this.unparsedPathLength;
    }

    /**
     * Whether the substitute name is relative to the directory containing the link. An absolute
     * target is expressed in the server's own namespace (a Windows server sends forms such as
     * {@code \??\C:\...}), which is not necessarily reachable through this share.
     *
     * @return true if SYMLINK_FLAG_RELATIVE is set
     */
    public boolean isRelative() {
        return this.relative;
    }

    /**
     * Returns the link target as the server stores it. This is the name to resolve against.
     *
     * @return the substitute name
     */
    public String getSubstituteName() {
        return this.substituteName;
    }

    /**
     * Returns the link target in a form meant for display, which may differ from the substitute
     * name and is not suitable for resolution.
     *
     * @return the print name
     */
    public String getPrintName() {
        return this.printName;
    }

    @Override
    public String toString() {
        return "Smb2SymlinkErrorResponse[substituteName=" + this.substituteName + ",printName=" + this.printName + ",relative="
                + this.relative + ",unparsedPathLength=" + this.unparsedPathLength + "]";
    }
}
