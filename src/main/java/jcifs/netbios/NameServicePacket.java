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

package jcifs.netbios;

import java.net.InetAddress;

import jcifs.Configuration;
import jcifs.util.Hexdump;

abstract class NameServicePacket {

    // opcode
    static final int QUERY = 0;
    static final int WACK = 7;

    // rcode
    static final int FMT_ERR = 0x1;
    static final int SRV_ERR = 0x2;
    static final int IMP_ERR = 0x4;
    static final int RFS_ERR = 0x5;
    static final int ACT_ERR = 0x6;
    static final int CFT_ERR = 0x7;

    // type/class
    static final int NB_IN = 0x00200001;
    static final int NBSTAT_IN = 0x00210001;
    static final int NB = 0x0020;
    static final int NBSTAT = 0x0021;
    static final int IN = 0x0001;
    static final int A = 0x0001;
    static final int NS = 0x0002;
    static final int NULL = 0x000a;

    static final int HEADER_LENGTH = 12;

    // header field offsets
    static final int OPCODE_OFFSET = 2;
    static final int QUESTION_OFFSET = 4;
    static final int ANSWER_OFFSET = 6;
    static final int AUTHORITY_OFFSET = 8;
    static final int ADDITIONAL_OFFSET = 10;

    static void writeInt2(final int val, final byte[] dst, int dstIndex) {
        dst[dstIndex] = (byte) (val >> 8 & 0xFF);
        dstIndex++;
        dst[dstIndex] = (byte) (val & 0xFF);
    }

    static void writeInt4(final int val, final byte[] dst, int dstIndex) {
        dst[dstIndex] = (byte) (val >> 24 & 0xFF);
        dstIndex++;
        dst[dstIndex++] = (byte) (val >> 16 & 0xFF);
        dst[dstIndex++] = (byte) (val >> 8 & 0xFF);
        dst[dstIndex] = (byte) (val & 0xFF);
    }

    static int readInt2(final byte[] src, final int srcIndex) {
        return ((src[srcIndex] & 0xFF) << 8) + (src[srcIndex + 1] & 0xFF);
    }

    static int readInt4(final byte[] src, final int srcIndex) {
        return ((src[srcIndex] & 0xFF) << 24) + ((src[srcIndex + 1] & 0xFF) << 16) + ((src[srcIndex + 2] & 0xFF) << 8)
                + (src[srcIndex + 3] & 0xFF);
    }

    static int readNameTrnId(final byte[] src, final int srcIndex) {
        return readInt2(src, srcIndex);
    }

    int addrIndex;
    NbtAddress[] addrEntry;

    int nameTrnId;

    int opCode, resultCode, questionCount, answerCount, authorityCount, additionalCount;
    boolean received, isResponse, isAuthAnswer, isTruncated, isRecurDesired, isRecurAvailable, isBroadcast;

    Name questionName;
    Name recordName;

    int questionType, questionClass, recordType, recordClass, ttl, rDataLength;

    InetAddress addr;
    protected Configuration config;

    NameServicePacket(final Configuration config) {
        this.config = config;
        this.isRecurDesired = true;
        this.isBroadcast = true;
        this.questionCount = 1;
        this.questionClass = IN;
    }

    int writeWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        dstIndex += writeHeaderWireFormat(dst, dstIndex);
        dstIndex += writeBodyWireFormat(dst, dstIndex);
        return dstIndex - start;
    }

    int readWireFormat(final byte[] src, int srcIndex) {
        final int start = srcIndex;
        srcIndex += readHeaderWireFormat(src, srcIndex);
        srcIndex += readBodyWireFormat(src, srcIndex);
        return srcIndex - start;
    }

    int writeHeaderWireFormat(final byte[] dst, final int dstIndex) {
        final int start = dstIndex;
        writeInt2(this.nameTrnId, dst, dstIndex);
        dst[dstIndex + OPCODE_OFFSET] = (byte) ((this.isResponse ? 0x80 : 0x00) + (this.opCode << 3 & 0x78)
                + (this.isAuthAnswer ? 0x04 : 0x00) + (this.isTruncated ? 0x02 : 0x00) + (this.isRecurDesired ? 0x01 : 0x00));
        dst[dstIndex + OPCODE_OFFSET + 1] =
                (byte) ((this.isRecurAvailable ? 0x80 : 0x00) + (this.isBroadcast ? 0x10 : 0x00) + (this.resultCode & 0x0F));
        writeInt2(this.questionCount, dst, start + QUESTION_OFFSET);
        writeInt2(this.answerCount, dst, start + ANSWER_OFFSET);
        writeInt2(this.authorityCount, dst, start + AUTHORITY_OFFSET);
        writeInt2(this.additionalCount, dst, start + ADDITIONAL_OFFSET);
        return HEADER_LENGTH;
    }

    int readHeaderWireFormat(final byte[] src, final int srcIndex) {
        this.nameTrnId = readInt2(src, srcIndex);
        this.isResponse = ((src[srcIndex + OPCODE_OFFSET] & 0x80) == 0) == false;
        this.opCode = (src[srcIndex + OPCODE_OFFSET] & 0x78) >> 3;
        this.isAuthAnswer = ((src[srcIndex + OPCODE_OFFSET] & 0x04) == 0) == false;
        this.isTruncated = ((src[srcIndex + OPCODE_OFFSET] & 0x02) == 0) == false;
        this.isRecurDesired = ((src[srcIndex + OPCODE_OFFSET] & 0x01) == 0) == false;
        this.isRecurAvailable = ((src[srcIndex + OPCODE_OFFSET + 1] & 0x80) == 0) == false;
        this.isBroadcast = ((src[srcIndex + OPCODE_OFFSET + 1] & 0x10) == 0) == false;
        this.resultCode = src[srcIndex + OPCODE_OFFSET + 1] & 0x0F;
        this.questionCount = readInt2(src, srcIndex + QUESTION_OFFSET);
        this.answerCount = readInt2(src, srcIndex + ANSWER_OFFSET);
        this.authorityCount = readInt2(src, srcIndex + AUTHORITY_OFFSET);
        this.additionalCount = readInt2(src, srcIndex + ADDITIONAL_OFFSET);
        return HEADER_LENGTH;
    }

    int writeQuestionSectionWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        dstIndex += this.questionName.writeWireFormat(dst, dstIndex);
        writeInt2(this.questionType, dst, dstIndex);
        dstIndex += 2;
        writeInt2(this.questionClass, dst, dstIndex);
        dstIndex += 2;
        return dstIndex - start;
    }

    int readQuestionSectionWireFormat(final byte[] src, int srcIndex) {
        final int start = srcIndex;
        srcIndex += this.questionName.readWireFormat(src, srcIndex);
        this.questionType = readInt2(src, srcIndex);
        srcIndex += 2;
        this.questionClass = readInt2(src, srcIndex);
        srcIndex += 2;
        return srcIndex - start;
    }

    int writeResourceRecordWireFormat(final byte[] dst, int dstIndex) {
        final int start = dstIndex;
        if (this.recordName == this.questionName) {
            dst[dstIndex] = (byte) 0xC0; // label string pointer to
            dstIndex++;
            dst[dstIndex++] = (byte) 0x0C; // questionName (offset 12)
        } else {
            dstIndex += this.recordName.writeWireFormat(dst, dstIndex);
        }
        writeInt2(this.recordType, dst, dstIndex);
        dstIndex += 2;
        writeInt2(this.recordClass, dst, dstIndex);
        dstIndex += 2;
        writeInt4(this.ttl, dst, dstIndex);
        dstIndex += 4;
        this.rDataLength = writeRDataWireFormat(dst, dstIndex + 2);
        writeInt2(this.rDataLength, dst, dstIndex);
        dstIndex += 2 + this.rDataLength;
        return dstIndex - start;
    }

    int readResourceRecordWireFormat(final byte[] src, int srcIndex) {
        final int start = srcIndex;
        int end;

        if ((src[srcIndex] & 0xC0) == 0xC0) {
            this.recordName = this.questionName; // label string pointer to questionName
            srcIndex += 2;
        } else {
            srcIndex += this.recordName.readWireFormat(src, srcIndex);
        }
        this.recordType = readInt2(src, srcIndex);
        srcIndex += 2;
        this.recordClass = readInt2(src, srcIndex);
        srcIndex += 2;
        this.ttl = readInt4(src, srcIndex);
        srcIndex += 4;
        this.rDataLength = readInt2(src, srcIndex);
        srcIndex += 2;

        this.addrEntry = new NbtAddress[this.rDataLength / 6];
        end = srcIndex + this.rDataLength;
        /*
         * Apparently readRDataWireFormat can return 0 if resultCode != 0 in
         * which case this will look indefinitely. Putting this else clause around
         * the loop might fix that. But I would need to see a capture to confirm.
         * if (resultCode != 0) {
         * srcIndex += rDataLength;
         * } else {
         */
        for (this.addrIndex = 0; srcIndex < end; this.addrIndex++) {
            srcIndex += readRDataWireFormat(src, srcIndex);
        }

        return srcIndex - start;
    }

    abstract int writeBodyWireFormat(byte[] dst, int dstIndex);

    abstract int readBodyWireFormat(byte[] src, int srcIndex);

    abstract int writeRDataWireFormat(byte[] dst, int dstIndex);

    abstract int readRDataWireFormat(byte[] src, int srcIndex);

    @Override
    public String toString() {
        String opCodeString, resultCodeString, questionTypeString, recordTypeString;

        opCodeString = switch (this.opCode) {
        case QUERY -> "QUERY";
        case WACK -> "WACK";
        default -> Integer.toString(this.opCode);
        };
        resultCodeString = switch (this.resultCode) {
        case FMT_ERR -> "FMT_ERR";
        case SRV_ERR -> "SRV_ERR";
        case IMP_ERR -> "IMP_ERR";
        case RFS_ERR -> "RFS_ERR";
        case ACT_ERR -> "ACT_ERR";
        case CFT_ERR -> "CFT_ERR";
        default -> "0x" + Hexdump.toHexString(this.resultCode, 1);
        };
        questionTypeString = switch (this.questionType) {
        case NB -> "NB";
        case NBSTAT -> "NBSTAT";
        default -> "0x" + Hexdump.toHexString(this.questionType, 4);
        };
        recordTypeString = switch (this.recordType) {
        case A -> "A";
        case NS -> "NS";
        case NULL -> "NULL";
        case NB -> "NB";
        case NBSTAT -> "NBSTAT";
        default -> "0x" + Hexdump.toHexString(this.recordType, 4);
        };

        return ("nameTrnId=" + this.nameTrnId + ",isResponse=" + this.isResponse + ",opCode=" + opCodeString + ",isAuthAnswer="
                + this.isAuthAnswer + ",isTruncated=" + this.isTruncated + ",isRecurAvailable=" + this.isRecurAvailable + ",isRecurDesired="
                + this.isRecurDesired + ",isBroadcast=" + this.isBroadcast + ",resultCode=" + resultCodeString + ",questionCount="
                + this.questionCount + ",answerCount=" + this.answerCount + ",authorityCount=" + this.authorityCount + ",additionalCount="
                + this.additionalCount + ",questionName=" + this.questionName + ",questionType=" + questionTypeString + ",questionClass="
                + (this.questionClass == IN ? "IN" : "0x" + Hexdump.toHexString(this.questionClass, 4)) + ",recordName=" + this.recordName
                + ",recordType=" + recordTypeString + ",recordClass="
                + (this.recordClass == IN ? "IN" : "0x" + Hexdump.toHexString(this.recordClass, 4)) + ",ttl=" + this.ttl + ",rDataLength="
                + this.rDataLength);
    }
}
