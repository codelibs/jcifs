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
package org.codelibs.jcifs.smb.internal.smb1.com;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for the {@link SmbComOpenAndX} class.
 *
 * <p>
 * The parameter words of an SMB_COM_OPEN_ANDX request occupy 26 bytes once the four AndX bytes have
 * been accounted for: Flags(2), AccessMode(2), SearchAttrs(2), FileAttrs(2), CreationTime(4),
 * OpenFunction(2), AllocationSize(4) and eight reserved bytes.
 * </p>
 */
public class SmbComOpenAndXTest {

    /** Size of the parameter words that {@link SmbComOpenAndX} encodes. */
    private static final int PARAMETER_WORDS_SIZE = 26;

    /** ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, the fixed search attributes of the request. */
    private static final int EXPECTED_SEARCH_ATTRIBUTES = SmbConstants.ATTR_DIRECTORY | SmbConstants.ATTR_HIDDEN | SmbConstants.ATTR_SYSTEM;

    private PropertyConfiguration config;

    @BeforeEach
    public void setUp() throws CIFSException {
        this.config = new PropertyConfiguration(new Properties());
    }

    private SmbComOpenAndX request(final int access, final int shareAccess, final int flags, final int fileAttributes) {
        return new SmbComOpenAndX(this.config, "test.txt", access, shareAccess, flags, fileAttributes, null);
    }

    private static int desiredAccessOf(final SmbComOpenAndX request) {
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE];
        request.writeParameterWordsWireFormat(dst, 0);
        return SMBUtil.readInt2(dst, 2);
    }

    private static int openFunctionOf(final SmbComOpenAndX request) {
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE];
        request.writeParameterWordsWireFormat(dst, 0);
        return SMBUtil.readInt2(dst, 12);
    }

    @Test
    @DisplayName("The command is SMB_COM_OPEN_ANDX")
    public void shouldUseOpenAndXCommand() {
        assertEquals(ServerMessageBlock.SMB_COM_OPEN_ANDX, request(SmbConstants.O_RDONLY, SmbConstants.FILE_SHARE_READ, 0, 0).getCommand());
    }

    @Test
    @DisplayName("Every parameter word sits at its documented offset")
    public void shouldWriteAllParameterWords() {
        final SmbComOpenAndX request =
                request(SmbConstants.O_RDONLY, SmbConstants.FILE_SHARE_READ | SmbConstants.FILE_SHARE_WRITE, 0, SmbConstants.ATTR_NORMAL);
        request.tflags = SmbComOpenAndX.FLAGS_REQUEST_OPLOCK;
        request.allocationSize = 0x0001_0000;
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE];

        assertEquals(PARAMETER_WORDS_SIZE, request.writeParameterWordsWireFormat(dst, 0));

        assertEquals(SmbComOpenAndX.FLAGS_REQUEST_OPLOCK, SMBUtil.readInt2(dst, 0));
        assertEquals(SmbComOpenAndX.SHARING_DENY_NONE, SMBUtil.readInt2(dst, 2));
        assertEquals(EXPECTED_SEARCH_ATTRIBUTES, SMBUtil.readInt2(dst, 4));
        assertEquals(SmbConstants.ATTR_NORMAL, SMBUtil.readInt2(dst, 6));
        assertEquals(0, SMBUtil.readInt4(dst, 8), "the creation time is always sent as zero");
        assertEquals(SmbComOpenAndX.OPEN_FN_OPEN, SMBUtil.readInt2(dst, 12));
        assertEquals(0x0001_0000, SMBUtil.readInt4(dst, 14));
        assertArrayEquals(new byte[8], Arrays.copyOfRange(dst, 18, 26), "the trailing eight bytes are reserved and zero");
    }

    @Test
    @DisplayName("A creation time left over from an earlier encode is cleared before it is written")
    public void shouldAlwaysSendZeroCreationTime() {
        final SmbComOpenAndX request = request(SmbConstants.O_RDONLY, SmbConstants.FILE_SHARE_READ, 0, 0);
        request.creationTime = 0x7FFF_FFFF;
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE];

        request.writeParameterWordsWireFormat(dst, 0);

        assertEquals(0, SMBUtil.readInt4(dst, 8));
        assertEquals(0, request.creationTime, "the field itself is reset too");
    }

    @Test
    @DisplayName("The parameter words are written at the requested offset")
    public void shouldHonourTheWriteOffset() {
        final SmbComOpenAndX request = request(SmbConstants.O_RDONLY, SmbConstants.FILE_SHARE_READ, 0, 0);
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE + 8];

        assertEquals(PARAMETER_WORDS_SIZE, request.writeParameterWordsWireFormat(dst, 4));

        assertArrayEquals(new byte[4], Arrays.copyOfRange(dst, 0, 4), "nothing before the offset may be touched");
        assertEquals(EXPECTED_SEARCH_ATTRIBUTES, SMBUtil.readInt2(dst, 8));
    }

    @Test
    @DisplayName("Read write access collapses onto the write bit and the read bit is always cleared")
    public void shouldMapTheAccessMode() {
        assertEquals(SmbComOpenAndX.SHARING_DENY_NONE | 0x00,
                desiredAccessOf(request(SmbConstants.O_RDONLY, SmbConstants.FILE_SHARE_READ | SmbConstants.FILE_SHARE_WRITE, 0, 0)),
                "O_RDONLY is 0x1 and bit 0 is masked off again");
        assertEquals(SmbComOpenAndX.SHARING_DENY_NONE | 0x02,
                desiredAccessOf(request(SmbConstants.O_WRONLY, SmbConstants.FILE_SHARE_READ | SmbConstants.FILE_SHARE_WRITE, 0, 0)));
        assertEquals(SmbComOpenAndX.SHARING_DENY_NONE | 0x02,
                desiredAccessOf(request(SmbConstants.O_RDWR, SmbConstants.FILE_SHARE_READ | SmbConstants.FILE_SHARE_WRITE, 0, 0)),
                "O_RDWR is remapped onto the write only encoding");
    }

    @Test
    @DisplayName("The share access maps onto the sharing bits of the access mode")
    public void shouldMapTheShareAccess() {
        assertEquals(SmbComOpenAndX.SHARING_DENY_NONE,
                desiredAccessOf(request(SmbConstants.O_RDONLY, SmbConstants.FILE_SHARE_READ | SmbConstants.FILE_SHARE_WRITE, 0, 0)));
        assertEquals(SmbComOpenAndX.SHARING_DENY_READ_WRITE_EXECUTE,
                desiredAccessOf(request(SmbConstants.O_RDONLY, SmbConstants.FILE_NO_SHARE, 0, 0)));
        assertEquals(SmbComOpenAndX.SHARING_DENY_WRITE,
                desiredAccessOf(request(SmbConstants.O_RDONLY, SmbConstants.FILE_SHARE_READ, 0, 0)));
        assertEquals(SmbComOpenAndX.SHARING_DENY_READ_EXECUTE,
                desiredAccessOf(request(SmbConstants.O_RDONLY, SmbConstants.FILE_SHARE_WRITE, 0, 0)));
        assertEquals(SmbComOpenAndX.SHARING_DENY_WRITE,
                desiredAccessOf(request(SmbConstants.O_RDONLY, SmbConstants.FILE_SHARE_DELETE, 0, 0)),
                "delete sharing alone still denies write");
    }

    @Test
    @DisplayName("The open flags map onto the open function")
    public void shouldMapTheOpenFunction() {
        assertEquals(SmbComOpenAndX.OPEN_FN_OPEN, openFunctionOf(request(SmbConstants.O_RDONLY, SmbConstants.FILE_SHARE_READ, 0, 0)));
        assertEquals(SmbComOpenAndX.OPEN_FN_TRUNC,
                openFunctionOf(request(SmbConstants.O_RDONLY, SmbConstants.FILE_SHARE_READ, SmbConstants.O_TRUNC, 0)));
        assertEquals(SmbComOpenAndX.OPEN_FN_TRUNC | SmbComOpenAndX.OPEN_FN_CREATE, openFunctionOf(
                request(SmbConstants.O_RDONLY, SmbConstants.FILE_SHARE_READ, SmbConstants.O_TRUNC | SmbConstants.O_CREAT, 0)));
        assertEquals(SmbComOpenAndX.OPEN_FN_CREATE | SmbComOpenAndX.OPEN_FN_OPEN,
                openFunctionOf(request(SmbConstants.O_RDONLY, SmbConstants.FILE_SHARE_READ, SmbConstants.O_CREAT, 0)));
        assertEquals(SmbComOpenAndX.OPEN_FN_CREATE | SmbComOpenAndX.OPEN_FN_FAIL_IF_EXISTS, openFunctionOf(
                request(SmbConstants.O_RDONLY, SmbConstants.FILE_SHARE_READ, SmbConstants.O_CREAT | SmbConstants.O_EXCL, 0)));
    }

    @Test
    @DisplayName("The widest file attributes and allocation size fill their fields completely")
    public void shouldWriteMaximumValues() {
        final SmbComOpenAndX request = request(SmbConstants.O_RDONLY, SmbConstants.FILE_SHARE_READ, 0, 0xFFFF);
        request.tflags = 0xFFFF;
        request.allocationSize = 0xFFFF_FFFF;
        final byte[] dst = new byte[PARAMETER_WORDS_SIZE];

        assertEquals(PARAMETER_WORDS_SIZE, request.writeParameterWordsWireFormat(dst, 0));

        assertEquals(0xFFFF, SMBUtil.readInt2(dst, 0));
        assertEquals(0xFFFF, SMBUtil.readInt2(dst, 6));
        assertEquals(-1, SMBUtil.readInt4(dst, 14), "0xFFFFFFFF reads back as a signed -1");
    }

    @Test
    @DisplayName("An OEM file name is written as a NUL terminated string with no leading pad")
    public void shouldWriteAnOemFileName() {
        final SmbComOpenAndX request = request(SmbConstants.O_RDONLY, SmbConstants.FILE_SHARE_READ, 0, 0);
        request.setUseUnicode(false);
        final byte[] dst = new byte[32];

        final int written = request.writeBytesWireFormat(dst, 0);

        assertEquals("test.txt".length() + 1, written);
        assertEquals("test.txt", new String(dst, 0, "test.txt".length(), StandardCharsets.US_ASCII));
        assertEquals(0x00, dst["test.txt".length()]);
    }

    @Test
    @DisplayName("A Unicode file name is preceded by a pad byte and word aligned")
    public void shouldWriteAUnicodeFileName() {
        final SmbComOpenAndX request =
                new SmbComOpenAndX(this.config, "AB", SmbConstants.O_RDONLY, SmbConstants.FILE_SHARE_READ, 0, 0, null);
        request.setUseUnicode(true);
        final byte[] dst = new byte[32];

        final int written = request.writeBytesWireFormat(dst, 0);

        // pad byte, word alignment byte, "AB" in UTF-16LE, two byte terminator
        assertEquals(8, written);
        assertArrayEquals(new byte[] { 0x00, 0x00, 'A', 0x00, 'B', 0x00, 0x00, 0x00 }, Arrays.copyOfRange(dst, 0, 8));
    }

    @Test
    @DisplayName("A request never decodes anything")
    public void shouldReadNothing() {
        final SmbComOpenAndX request = request(SmbConstants.O_RDONLY, SmbConstants.FILE_SHARE_READ, 0, 0);

        assertEquals(0, request.readParameterWordsWireFormat(new byte[32], 0));
        assertEquals(0, request.readBytesWireFormat(new byte[32], 0));
    }

    @Test
    @DisplayName("toString names the message and does not throw")
    public void shouldRenderToString() {
        final String rendered = request(SmbConstants.O_RDONLY, SmbConstants.FILE_SHARE_READ, 0, 0).toString();

        assertNotNull(rendered);
        assertTrue(rendered.startsWith("SmbComOpenAndX["), rendered);
        assertTrue(rendered.contains("fileName=test.txt"), rendered);
        assertTrue(rendered.endsWith("]"), rendered);
    }
}
