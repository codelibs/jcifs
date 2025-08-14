/* jcifs smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
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

package jcifs.smb1.smb1;

import java.io.UnsupportedEncodingException;
import java.util.Date;

import jcifs.smb1.util.Hexdump;
import jcifs.smb1.util.LogStream;
import jcifs.smb1.util.transport.Request;
import jcifs.smb1.util.transport.Response;

abstract class ServerMessageBlock extends Response implements Request, SmbConstants {

    static LogStream log = LogStream.getInstance();

    static final byte[] header = { (byte) 0xFF, (byte) 'S', (byte) 'M', (byte) 'B', (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };

    static void writeInt2(final long val, final byte[] dst, int dstIndex) {
        dst[dstIndex] = (byte) val;
        dstIndex++;
        dst[dstIndex] = (byte) (val >> 8);
    }

    static void writeInt4(long val, final byte[] dst, int dstIndex) {
        dst[dstIndex] = (byte) val;
        dstIndex++;
        dst[dstIndex] = (byte) (val >>= 8);
        dst[++dstIndex] = (byte) (val >>= 8);
        dst[++dstIndex] = (byte) (val >> 8);
    }

    static int readInt2(final byte[] src, final int srcIndex) {
        return (src[srcIndex] & 0xFF) + ((src[srcIndex + 1] & 0xFF) << 8);
    }

    static int readInt4(final byte[] src, final int srcIndex) {
        return (src[srcIndex] & 0xFF) + ((src[srcIndex + 1] & 0xFF) << 8) + ((src[srcIndex + 2] & 0xFF) << 16)
                + ((src[srcIndex + 3] & 0xFF) << 24);
    }

    static long readInt8(final byte[] src, final int srcIndex) {
        return (readInt4(src, srcIndex) & 0xFFFFFFFFL) + ((long) readInt4(src, srcIndex + 4) << 32);
    }

    static void writeInt8(long val, final byte[] dst, int dstIndex) {
        dst[dstIndex] = (byte) val;
        dstIndex++;
        dst[dstIndex] = (byte) (val >>= 8);
        dst[++dstIndex] = (byte) (val >>= 8);
        dst[++dstIndex] = (byte) (val >>= 8);
        dst[++dstIndex] = (byte) (val >>= 8);
        dst[++dstIndex] = (byte) (val >>= 8);
        dst[++dstIndex] = (byte) (val >>= 8);
        dst[++dstIndex] = (byte) (val >> 8);
    }

    static long readTime(final byte[] src, final int srcIndex) {
        final int low = readInt4(src, srcIndex);
        final int hi = readInt4(src, srcIndex + 4);
        final long t = (long) hi << 32L | low & 0xFFFFFFFFL;
        return t / 10000L - MILLISECONDS_BETWEEN_1970_AND_1601;
    }

    static void writeTime(long t, final byte[] dst, final int dstIndex) {
        if (t != 0L) {
            t = (t + MILLISECONDS_BETWEEN_1970_AND_1601) * 10000L;
        }
        writeInt8(t, dst, dstIndex);
    }

    static long readUTime(final byte[] buffer, final int bufferIndex) {
        return readInt4(buffer, bufferIndex) * 1000L;
    }

    static void writeUTime(long t, final byte[] dst, final int dstIndex) {
        if (t == 0L || t == 0xFFFFFFFFFFFFFFFFL) {
            writeInt4(0xFFFFFFFF, dst, dstIndex);
            return;
        }
        synchronized (TZ) {
            if (TZ.inDaylightTime(new Date())) {
                // in DST
                if (TZ.inDaylightTime(new Date(t))) {
                    // t also in DST so no correction
                } else {
                    // t not in DST so subtract 1 hour
                    t -= 3600000;
                }
            } else // not in DST
            if (TZ.inDaylightTime(new Date(t))) {
                // t is in DST so add 1 hour
                t += 3600000;
            } else {
                // t isn't in DST either
            }
        }
        writeInt4((int) (t / 1000L), dst, dstIndex);
    }

    /*
     * These are all the smbs supported by this library. This includes requests
     * and well as their responses for each type however the actuall implementations
     * of the readXxxWireFormat and writeXxxWireFormat methods may not be in
     * place. For example at the time of this writing the readXxxWireFormat
     * for requests and the writeXxxWireFormat for responses are not implemented
     * and simply return 0. These would need to be completed for a server
     * implementation.
     */

    static final byte SMB_COM_CREATE_DIRECTORY = (byte) 0x00;
    static final byte SMB_COM_DELETE_DIRECTORY = (byte) 0x01;
    static final byte SMB_COM_CLOSE = (byte) 0x04;
    static final byte SMB_COM_DELETE = (byte) 0x06;
    static final byte SMB_COM_RENAME = (byte) 0x07;
    static final byte SMB_COM_QUERY_INFORMATION = (byte) 0x08;
    static final byte SMB_COM_WRITE = (byte) 0x0B;
    static final byte SMB_COM_CHECK_DIRECTORY = (byte) 0x10;
    static final byte SMB_COM_TRANSACTION = (byte) 0x25;
    static final byte SMB_COM_TRANSACTION_SECONDARY = (byte) 0x26;
    static final byte SMB_COM_MOVE = (byte) 0x2A;
    static final byte SMB_COM_ECHO = (byte) 0x2B;
    static final byte SMB_COM_OPEN_ANDX = (byte) 0x2D;
    static final byte SMB_COM_READ_ANDX = (byte) 0x2E;
    static final byte SMB_COM_WRITE_ANDX = (byte) 0x2F;
    static final byte SMB_COM_TRANSACTION2 = (byte) 0x32;
    static final byte SMB_COM_FIND_CLOSE2 = (byte) 0x34;
    static final byte SMB_COM_TREE_DISCONNECT = (byte) 0x71;
    static final byte SMB_COM_NEGOTIATE = (byte) 0x72;
    static final byte SMB_COM_SESSION_SETUP_ANDX = (byte) 0x73;
    static final byte SMB_COM_LOGOFF_ANDX = (byte) 0x74;
    static final byte SMB_COM_TREE_CONNECT_ANDX = (byte) 0x75;
    static final byte SMB_COM_NT_TRANSACT = (byte) 0xA0;
    static final byte SMB_COM_NT_TRANSACT_SECONDARY = (byte) 0xA1;
    static final byte SMB_COM_NT_CREATE_ANDX = (byte) 0xA2;

    /*
     * Some fields specify the offset from the beginning of the header. This
     * field should be used for calculating that. This would likely be zero
     * but an implemantation that encorporates the transport header(for
     * efficiency) might use a different initial bufferIndex. For example,
     * to eliminate copying data when writing NbtSession data one might
     * manage that 4 byte header specifically and therefore the initial
     * bufferIndex, and thus headerStart, would be 4).(NOTE: If one where
     * looking for a way to improve perfomance this is precisly what you
     * would want to do as the jcifs.smb1.netbios.SocketXxxputStream classes
     * arraycopy all data read or written into a new buffer shifted over 4!)
     */

    byte command, flags;
    int headerStart, length, batchLevel, errorCode, flags2, tid, pid, uid, mid, wordCount, byteCount;
    boolean useUnicode, received, extendedSecurity;
    long responseTimeout = 1;
    int signSeq;
    boolean verifyFailed;
    NtlmPasswordAuthentication auth = null;
    String path;
    SigningDigest digest = null;
    ServerMessageBlock response;

    ServerMessageBlock() {
        flags = (byte) (FLAGS_PATH_NAMES_CASELESS | FLAGS_PATH_NAMES_CANONICALIZED);
        pid = PID;
        batchLevel = 0;
    }

    void reset() {
        flags = (byte) (FLAGS_PATH_NAMES_CASELESS | FLAGS_PATH_NAMES_CANONICALIZED);
        flags2 = 0;
        errorCode = 0;
        received = false;
        digest = null;
    }

    int writeString(final String str, final byte[] dst, final int dstIndex) {
        return writeString(str, dst, dstIndex, useUnicode);
    }

    int writeString(final String str, final byte[] dst, int dstIndex, final boolean useUnicode) {
        final int start = dstIndex;

        try {
            if (useUnicode) {
                // Unicode requires word alignment
                if ((dstIndex - headerStart) % 2 != 0) {
                    dst[dstIndex++] = (byte) '\0';
                }
                System.arraycopy(str.getBytes(UNI_ENCODING), 0, dst, dstIndex, str.length() * 2);
                dstIndex += str.length() * 2;
                dst[dstIndex] = (byte) '\0';
                dstIndex++;
                dst[dstIndex++] = (byte) '\0';
            } else {
                final byte[] b = str.getBytes(OEM_ENCODING);
                System.arraycopy(b, 0, dst, dstIndex, b.length);
                dstIndex += b.length;
                dst[dstIndex] = (byte) '\0';
                dstIndex++;
            }
        } catch (final UnsupportedEncodingException uee) {
            if (LogStream.level > 1) {
                uee.printStackTrace(log);
            }
        }

        return dstIndex - start;
    }

    String readString(final byte[] src, final int srcIndex) {
        return readString(src, srcIndex, 256, useUnicode);
    }

    String readString(final byte[] src, int srcIndex, final int maxLen, final boolean useUnicode) {
        int len = 0;
        String str = null;
        try {
            if (useUnicode) {
                // Unicode requires word alignment
                if ((srcIndex - headerStart) % 2 != 0) {
                    srcIndex++;
                }
                while (src[srcIndex + len] != (byte) 0x00 || src[srcIndex + len + 1] != (byte) 0x00) {
                    len += 2;
                    if (len > maxLen) {
                        if (LogStream.level > 0) {
                            Hexdump.hexdump(System.err, src, srcIndex, maxLen < 128 ? maxLen + 8 : 128);
                        }
                        throw new RuntimeException("zero termination not found");
                    }
                }
                str = new String(src, srcIndex, len, UNI_ENCODING);
            } else {
                while (src[srcIndex + len] != (byte) 0x00) {
                    len++;
                    if (len > maxLen) {
                        if (LogStream.level > 0) {
                            Hexdump.hexdump(System.err, src, srcIndex, maxLen < 128 ? maxLen + 8 : 128);
                        }
                        throw new RuntimeException("zero termination not found");
                    }
                }
                str = new String(src, srcIndex, len, OEM_ENCODING);
            }
        } catch (final UnsupportedEncodingException uee) {
            if (LogStream.level > 1) {
                uee.printStackTrace(log);
            }
        }
        return str;
    }

    String readString(final byte[] src, int srcIndex, final int srcEnd, final int maxLen, final boolean useUnicode) {
        int len = 0;
        String str = null;
        try {
            if (useUnicode) {
                // Unicode requires word alignment
                if ((srcIndex - headerStart) % 2 != 0) {
                    srcIndex++;
                }
                for (len = 0; srcIndex + len + 1 < srcEnd; len += 2) {
                    if (src[srcIndex + len] == (byte) 0x00 && src[srcIndex + len + 1] == (byte) 0x00) {
                        break;
                    }
                    if (len > maxLen) {
                        if (LogStream.level > 0) {
                            Hexdump.hexdump(System.err, src, srcIndex, maxLen < 128 ? maxLen + 8 : 128);
                        }
                        throw new RuntimeException("zero termination not found");
                    }
                }
                str = new String(src, srcIndex, len, UNI_ENCODING);
            } else {
                for (len = 0; srcIndex < srcEnd; len++) {
                    if (src[srcIndex + len] == (byte) 0x00) {
                        break;
                    }
                    if (len > maxLen) {
                        if (LogStream.level > 0) {
                            Hexdump.hexdump(System.err, src, srcIndex, maxLen < 128 ? maxLen + 8 : 128);
                        }
                        throw new RuntimeException("zero termination not found");
                    }
                }
                str = new String(src, srcIndex, len, OEM_ENCODING);
            }
        } catch (final UnsupportedEncodingException uee) {
            if (LogStream.level > 1) {
                uee.printStackTrace(log);
            }
        }
        return str;
    }

    int stringWireLength(final String str, final int offset) {
        int len = str.length() + 1;
        if (useUnicode) {
            len = str.length() * 2 + 2;
            len = offset % 2 != 0 ? len + 1 : len;
        }
        return len;
    }

    int readStringLength(final byte[] src, final int srcIndex, final int max) {
        int len = 0;
        while (src[srcIndex + len] != (byte) 0x00) {
            if (len++ > max) {
                throw new RuntimeException("zero termination not found: " + this);
            }
        }
        return len;
    }

    int encode(final byte[] dst, int dstIndex) {
        final int start = headerStart = dstIndex;

        dstIndex += writeHeaderWireFormat(dst, dstIndex);
        wordCount = writeParameterWordsWireFormat(dst, dstIndex + 1);
        dst[dstIndex] = (byte) (wordCount / 2 & 0xFF);
        dstIndex++;
        dstIndex += wordCount;
        wordCount /= 2;
        byteCount = writeBytesWireFormat(dst, dstIndex + 2);
        dst[dstIndex++] = (byte) (byteCount & 0xFF);
        dst[dstIndex++] = (byte) (byteCount >> 8 & 0xFF);
        dstIndex += byteCount;

        length = dstIndex - start;

        if (digest != null) {
            digest.sign(dst, headerStart, length, this, response);
        }

        return length;
    }

    int decode(final byte[] buffer, int bufferIndex) {
        final int start = headerStart = bufferIndex;

        bufferIndex += readHeaderWireFormat(buffer, bufferIndex);

        wordCount = buffer[bufferIndex];
        bufferIndex++;
        if (wordCount != 0) {
            int n = readParameterWordsWireFormat(buffer, bufferIndex);
            if ((n != wordCount * 2) && (LogStream.level >= 5)) {
                log.println("wordCount * 2=" + wordCount * 2 + " but readParameterWordsWireFormat returned " + n);
            }
            bufferIndex += wordCount * 2;
        }

        byteCount = readInt2(buffer, bufferIndex);
        bufferIndex += 2;

        if (byteCount != 0) {
            int n = readBytesWireFormat(buffer, bufferIndex);
            if ((n != byteCount) && (LogStream.level >= 5)) {
                log.println("byteCount=" + byteCount + " but readBytesWireFormat returned " + n);
            }
            // Don't think we can rely on n being correct here. Must use byteCount.
            // Last paragraph of section 3.13.3 eludes to this.

            bufferIndex += byteCount;
        }

        length = bufferIndex - start;
        return length;
    }

    int writeHeaderWireFormat(final byte[] dst, int dstIndex) {
        System.arraycopy(header, 0, dst, dstIndex, header.length);
        dst[dstIndex + CMD_OFFSET] = command;
        dst[dstIndex + FLAGS_OFFSET] = flags;
        writeInt2(flags2, dst, dstIndex + FLAGS_OFFSET + 1);
        dstIndex += TID_OFFSET;
        writeInt2(tid, dst, dstIndex);
        writeInt2(pid, dst, dstIndex + 2);
        writeInt2(uid, dst, dstIndex + 4);
        writeInt2(mid, dst, dstIndex + 6);
        return HEADER_LENGTH;
    }

    int readHeaderWireFormat(final byte[] buffer, final int bufferIndex) {
        command = buffer[bufferIndex + CMD_OFFSET];
        errorCode = readInt4(buffer, bufferIndex + ERROR_CODE_OFFSET);
        flags = buffer[bufferIndex + FLAGS_OFFSET];
        flags2 = readInt2(buffer, bufferIndex + FLAGS_OFFSET + 1);
        tid = readInt2(buffer, bufferIndex + TID_OFFSET);
        pid = readInt2(buffer, bufferIndex + TID_OFFSET + 2);
        uid = readInt2(buffer, bufferIndex + TID_OFFSET + 4);
        mid = readInt2(buffer, bufferIndex + TID_OFFSET + 6);
        return HEADER_LENGTH;
    }

    boolean isResponse() {
        return (flags & FLAGS_RESPONSE) == FLAGS_RESPONSE;
    }

    /*
     * For this packet deconstruction technique to work for
     * other networking protocols the InputStream may need
     * to be passed to the readXxxWireFormat methods. This is
     * actually purer. However, in the case of smb we know the
     * wordCount and byteCount. And since every subclass of
     * ServerMessageBlock would have to perform the same read
     * operation on the input stream, we might as will pull that
     * common functionality into the superclass and read wordCount
     * and byteCount worth of data.
     *
     * We will still use the readXxxWireFormat return values to
     * indicate how many bytes(note: readParameterWordsWireFormat
     * returns bytes read and not the number of words(but the
     * wordCount member DOES store the number of words)) we
     * actually read. Incedentally this is important to the
     * AndXServerMessageBlock class that needs to potentially
     * read in another smb's parameter words and bytes based on
     * information in it's andxCommand, andxOffset, ...etc.
     */

    abstract int writeParameterWordsWireFormat(byte[] dst, int dstIndex);

    abstract int writeBytesWireFormat(byte[] dst, int dstIndex);

    abstract int readParameterWordsWireFormat(byte[] buffer, int bufferIndex);

    abstract int readBytesWireFormat(byte[] buffer, int bufferIndex);

    @Override
    public int hashCode() {
        return mid;
    }

    @Override
    public boolean equals(final Object obj) {
        return obj instanceof ServerMessageBlock && ((ServerMessageBlock) obj).mid == mid;
    }

    @Override
    public String toString() {
        String c = switch (command) {
        case SMB_COM_NEGOTIATE -> "SMB_COM_NEGOTIATE";
        case SMB_COM_SESSION_SETUP_ANDX -> "SMB_COM_SESSION_SETUP_ANDX";
        case SMB_COM_TREE_CONNECT_ANDX -> "SMB_COM_TREE_CONNECT_ANDX";
        case SMB_COM_QUERY_INFORMATION -> "SMB_COM_QUERY_INFORMATION";
        case SMB_COM_CHECK_DIRECTORY -> "SMB_COM_CHECK_DIRECTORY";
        case SMB_COM_TRANSACTION -> "SMB_COM_TRANSACTION";
        case SMB_COM_TRANSACTION2 -> "SMB_COM_TRANSACTION2";
        case SMB_COM_TRANSACTION_SECONDARY -> "SMB_COM_TRANSACTION_SECONDARY";
        case SMB_COM_FIND_CLOSE2 -> "SMB_COM_FIND_CLOSE2";
        case SMB_COM_TREE_DISCONNECT -> "SMB_COM_TREE_DISCONNECT";
        case SMB_COM_LOGOFF_ANDX -> "SMB_COM_LOGOFF_ANDX";
        case SMB_COM_ECHO -> "SMB_COM_ECHO";
        case SMB_COM_MOVE -> "SMB_COM_MOVE";
        case SMB_COM_RENAME -> "SMB_COM_RENAME";
        case SMB_COM_DELETE -> "SMB_COM_DELETE";
        case SMB_COM_DELETE_DIRECTORY -> "SMB_COM_DELETE_DIRECTORY";
        case SMB_COM_NT_CREATE_ANDX -> "SMB_COM_NT_CREATE_ANDX";
        case SMB_COM_OPEN_ANDX -> "SMB_COM_OPEN_ANDX";
        case SMB_COM_READ_ANDX -> "SMB_COM_READ_ANDX";
        case SMB_COM_CLOSE -> "SMB_COM_CLOSE";
        case SMB_COM_WRITE_ANDX -> "SMB_COM_WRITE_ANDX";
        case SMB_COM_CREATE_DIRECTORY -> "SMB_COM_CREATE_DIRECTORY";
        case SMB_COM_NT_TRANSACT -> "SMB_COM_NT_TRANSACT";
        case SMB_COM_NT_TRANSACT_SECONDARY -> "SMB_COM_NT_TRANSACT_SECONDARY";
        default -> "UNKNOWN";
        };
        final String str = errorCode == 0 ? "0" : SmbException.getMessageByCode(errorCode);
        return "command=" + c + ",received=" + received + ",errorCode=" + str + ",flags=0x" + Hexdump.toHexString(flags & 0xFF, 4)
                + ",flags2=0x" + Hexdump.toHexString(flags2, 4) + ",signSeq=" + signSeq + ",tid=" + tid + ",pid=" + pid + ",uid=" + uid
                + ",mid=" + mid + ",wordCount=" + wordCount + ",byteCount=" + byteCount;
    }
}
