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
     * <p>
     * When the response carries error contexts, each is tried in turn: MS-SMB2 2.2.2 permits more
     * than one, and does not promise the symbolic link context comes first. A context is accepted
     * only if its payload carries the SYML tag, which identifies it more precisely than ErrorId
     * would.
     * </p>
     *
     * @param errorData the raw ErrorData of the SMB2 error response
     * @param errorContextCount the response's ErrorContextCount; non-zero means the payload is
     *            wrapped in one or more SMB2 ERROR Contexts, as SMB 3.1.1 does
     * @return the decoded symbolic link error response
     * @throws SMBProtocolDecodingException if the data is absent, truncated, or carries no symbolic
     *             link error response
     */
    public static Smb2SymlinkErrorResponse decode(final byte[] errorData, final int errorContextCount) throws SMBProtocolDecodingException {
        if (errorData == null) {
            throw new SMBProtocolDecodingException("Symlink error response carries no error data");
        }
        if (errorContextCount <= 0) {
            return decodeSymlinkResponse(errorData, 0, errorData.length);
        }

        SMBProtocolDecodingException failure = null;
        int bufferIndex = 0;
        for (int i = 0; i < errorContextCount; i++) {
            if (bufferIndex > errorData.length - ERROR_CONTEXT_HEADER_SIZE) {
                break;
            }
            final int contextDataLength = SMBUtil.readInt4(errorData, bufferIndex);
            final int contextDataIndex = bufferIndex + ERROR_CONTEXT_HEADER_SIZE;
            if (contextDataLength < 0 || contextDataLength > errorData.length - contextDataIndex) {
                throw new SMBProtocolDecodingException("SMB2 error context claims " + contextDataLength + " bytes but only "
                        + (errorData.length - contextDataIndex) + " are present");
            }
            try {
                return decodeSymlinkResponse(errorData, contextDataIndex, contextDataLength);
            } catch (final SMBProtocolDecodingException e) {
                // not the symbolic link context, or a malformed one: keep looking
                failure = e;
            }
            // each context starts on an 8 byte boundary relative to the start of the error response,
            // which is where this buffer begins
            bufferIndex = contextDataIndex + contextDataLength;
            bufferIndex += (8 - bufferIndex % 8) % 8;
        }
        if (failure != null) {
            throw failure;
        }
        throw new SMBProtocolDecodingException("No symbolic link error context in " + errorContextCount + " contexts");
    }

    /**
     * Decodes one SMB2_SYMLINK_ERROR_RESPONSE. Every read is bounded by the declared lengths rather
     * than by the size of the enclosing buffer, so a structure that overstates its own extent cannot
     * reach whatever happens to follow it.
     *
     * @param errorData the buffer to read from
     * @param start where the structure begins
     * @param length how many bytes the enclosing context declares
     */
    private static Smb2SymlinkErrorResponse decodeSymlinkResponse(final byte[] errorData, final int start, final int length)
            throws SMBProtocolDecodingException {
        if (length < FIXED_SIZE) {
            throw new SMBProtocolDecodingException("Truncated symlink error response: " + length + " bytes");
        }

        final int symLinkLength = SMBUtil.readInt4(errorData, start);
        final int symLinkErrorTag = SMBUtil.readInt4(errorData, start + 4);
        final int reparseTag = SMBUtil.readInt4(errorData, start + 8);

        if (symLinkErrorTag != SYMLINK_ERROR_TAG) {
            throw new SMBProtocolDecodingException(
                    "Not a symlink error response, SymLinkErrorTag is 0x" + Integer.toHexString(symLinkErrorTag));
        }
        if (reparseTag != IO_REPARSE_TAG_SYMLINK) {
            throw new SMBProtocolDecodingException("Unsupported reparse tag 0x" + Integer.toHexString(reparseTag));
        }
        // SymLinkLength covers everything from SymLinkErrorTag onwards, and bounds the rest of the read
        if (symLinkLength < FIXED_SIZE - 4 || symLinkLength > length - 4) {
            throw new SMBProtocolDecodingException("Invalid SymLinkLength " + symLinkLength + " for " + length + " bytes");
        }

        final int reparseDataLength = SMBUtil.readInt2(errorData, start + 12);
        final int unparsedPathLength = SMBUtil.readInt2(errorData, start + 14);
        final int substituteNameOffset = SMBUtil.readInt2(errorData, start + 16);
        final int substituteNameLength = SMBUtil.readInt2(errorData, start + 18);
        final int printNameOffset = SMBUtil.readInt2(errorData, start + 20);
        final int printNameLength = SMBUtil.readInt2(errorData, start + 22);
        final int flags = SMBUtil.readInt4(errorData, start + 24);

        // ReparseDataLength covers the name offset/length fields, Flags, and PathBuffer
        if (reparseDataLength < REPARSE_DATA_HEADER_SIZE) {
            throw new SMBProtocolDecodingException("Invalid ReparseDataLength " + reparseDataLength);
        }
        final int pathBufferIndex = start + FIXED_SIZE;
        final int pathBufferLength = reparseDataLength - REPARSE_DATA_HEADER_SIZE;
        if (pathBufferLength > 4 + symLinkLength - FIXED_SIZE) {
            throw new SMBProtocolDecodingException("ReparseDataLength " + reparseDataLength + " overruns the symlink error response");
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
