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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for the {@link SmbComTreeConnectAndXResponse} class.
 *
 * <p>
 * The parameter words of an SMB_COM_TREE_CONNECT_ANDX response are the two byte OptionalSupport
 * field. The data bytes are the NUL terminated ASCII service string followed by the native file
 * system name, which is only read when the declared byte count leaves room for it.
 * </p>
 */
public class SmbComTreeConnectAndXResponseTest {

    /**
     * Exposes the inherited byte count so that the optional native file system name, which
     * {@code readBytesWireFormat} only reads when the byte count leaves room for it, can be tested
     * without decoding a whole SMB message.
     */
    private static final class ByteCountingResponse extends SmbComTreeConnectAndXResponse {

        ByteCountingResponse(final Configuration config) {
            super(config, null);
        }

        void declareByteCount(final int count) {
            this.byteCount = count;
        }
    }

    private PropertyConfiguration config;

    @BeforeEach
    public void setUp() throws CIFSException {
        this.config = new PropertyConfiguration(new Properties());
    }

    private static byte[] dataBytes(final String... values) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (final String value : values) {
            out.writeBytes(value.getBytes(StandardCharsets.US_ASCII));
            out.write(0x00);
        }
        out.writeBytes(new byte[4]);
        return out.toByteArray();
    }

    @Test
    @DisplayName("A response accepts the tree connect AndX command code")
    public void shouldCarryTheTreeConnectAndXCommand() {
        final SmbComTreeConnectAndXResponse response = new SmbComTreeConnectAndXResponse(this.config, null);

        assertEquals(0, response.getCommand(), "a bare response has no command until it is decoded");

        response.setCommand(ServerMessageBlock.SMB_COM_TREE_CONNECT_ANDX);
        assertEquals(ServerMessageBlock.SMB_COM_TREE_CONNECT_ANDX, response.getCommand());
    }

    @Test
    @DisplayName("A chained command is retained as the AndX of the response")
    public void shouldRetainTheChainedCommand() {
        final SmbComBlankResponse andx = new SmbComBlankResponse(this.config);

        assertSame(andx, new SmbComTreeConnectAndXResponse(this.config, andx).getAndx());
    }

    @Test
    @DisplayName("A fresh response has no service and an empty native file system")
    public void shouldStartEmpty() {
        final SmbComTreeConnectAndXResponse response = new SmbComTreeConnectAndXResponse(this.config, null);

        assertNull(response.getService());
        assertEquals("", response.getNativeFileSystem());
        assertFalse(response.isSupportSearchBits());
        assertFalse(response.isShareDfs());
    }

    @Test
    @DisplayName("The OptionalSupport field is two bytes wide and carries the search and DFS bits")
    public void shouldDecodeTheOptionalSupportBits() {
        assertOptionalSupport((byte) 0x00, false, false);
        assertOptionalSupport((byte) 0x01, true, false);
        assertOptionalSupport((byte) 0x02, false, true);
        assertOptionalSupport((byte) 0x03, true, true);
        assertOptionalSupport((byte) 0xFC, false, false, "unrelated bits are ignored");
    }

    private void assertOptionalSupport(final byte optionalSupport, final boolean searchBits, final boolean dfs) {
        assertOptionalSupport(optionalSupport, searchBits, dfs, "OptionalSupport 0x" + Integer.toHexString(optionalSupport & 0xFF));
    }

    private void assertOptionalSupport(final byte optionalSupport, final boolean searchBits, final boolean dfs, final String message) {
        final SmbComTreeConnectAndXResponse response = new SmbComTreeConnectAndXResponse(this.config, null);

        assertEquals(2, response.readParameterWordsWireFormat(new byte[] { optionalSupport, 0x00 }, 0), message);

        assertEquals(searchBits, response.isSupportSearchBits(), message);
        assertEquals(dfs, response.isShareDfs(), message);
    }

    @Test
    @DisplayName("The parameter words are decoded from the requested offset")
    public void shouldHonourTheReadOffset() {
        final SmbComTreeConnectAndXResponse response = new SmbComTreeConnectAndXResponse(this.config, null);

        assertEquals(2, response.readParameterWordsWireFormat(new byte[] { 0x00, 0x00, 0x03, 0x00 }, 2));

        assertTrue(response.isSupportSearchBits());
        assertTrue(response.isShareDfs());
    }

    @Test
    @DisplayName("With no declared byte count only the service string is read")
    public void shouldDecodeTheServiceOnly() {
        final SmbComTreeConnectAndXResponse response = new SmbComTreeConnectAndXResponse(this.config, null);

        final int read = response.readBytesWireFormat(dataBytes("A:", "NTFS"), 0);

        assertEquals("A:", response.getService());
        assertEquals(3, read, "the service string costs its length plus a NUL");
        assertEquals("", response.getNativeFileSystem(), "no byte count means no room for the file system name");
    }

    @Test
    @DisplayName("A declared byte count that leaves room makes the native file system name readable")
    public void shouldDecodeTheNativeFileSystem() {
        final ByteCountingResponse response = new ByteCountingResponse(this.config);
        response.setUseUnicode(false);
        response.declareByteCount(8);

        final int read = response.readBytesWireFormat(dataBytes("A:", "NTFS"), 0);

        assertEquals("A:", response.getService());
        assertEquals("NTFS", response.getNativeFileSystem());
        assertEquals(8, read);
    }

    @Test
    @DisplayName("A byte count that stops at the service string leaves the file system name empty")
    public void shouldSkipTheNativeFileSystemWhenTheByteCountIsExhausted() {
        final ByteCountingResponse response = new ByteCountingResponse(this.config);
        response.setUseUnicode(false);
        response.declareByteCount(3);

        final int read = response.readBytesWireFormat(dataBytes("IPC", "NTFS"), 0);

        assertEquals("IPC", response.getService());
        assertEquals("", response.getNativeFileSystem());
        assertEquals(4, read);
    }

    @Test
    @DisplayName("The data bytes are decoded from the requested offset")
    public void shouldHonourTheDataReadOffset() {
        final byte[] buffer = new byte[16];
        System.arraycopy(dataBytes("LPT1:"), 0, buffer, 4, 6);
        final SmbComTreeConnectAndXResponse response = new SmbComTreeConnectAndXResponse(this.config, null);

        assertEquals(6, response.readBytesWireFormat(buffer, 4));
        assertEquals("LPT1:", response.getService());
    }

    @Test
    @DisplayName("An empty service string is decoded as empty and costs one byte")
    public void shouldDecodeAnEmptyService() {
        final SmbComTreeConnectAndXResponse response = new SmbComTreeConnectAndXResponse(this.config, null);

        assertEquals(1, response.readBytesWireFormat(dataBytes(""), 0));
        assertEquals("", response.getService());
    }

    @Test
    @DisplayName("A TID of 0xFFFF is the only invalid one")
    public void shouldValidateTheTid() {
        final SmbComTreeConnectAndXResponse response = new SmbComTreeConnectAndXResponse(this.config, null);

        assertFalse(response.isValidTid(), "the TID starts out as the 0xFFFF placeholder");

        response.setTid(0x0001);
        assertTrue(response.isValidTid());

        response.setTid(0x0000);
        assertTrue(response.isValidTid(), "zero is a legal TID");

        response.setTid(0xFFFF);
        assertFalse(response.isValidTid());
    }

    @Test
    @DisplayName("A response never encodes anything")
    public void shouldNotEncodeAnything() {
        final SmbComTreeConnectAndXResponse response = new SmbComTreeConnectAndXResponse(this.config, null);
        final byte[] dst = new byte[16];

        assertEquals(0, response.writeParameterWordsWireFormat(dst, 0));
        assertEquals(0, response.writeBytesWireFormat(dst, 0));
        assertArrayEquals(new byte[16], dst);
    }

    @Test
    @DisplayName("toString names the message and does not throw")
    public void shouldRenderToString() {
        final ByteCountingResponse response = new ByteCountingResponse(this.config);
        response.setUseUnicode(false);
        response.declareByteCount(8);
        response.readParameterWordsWireFormat(new byte[] { 0x03, 0x00 }, 0);
        response.readBytesWireFormat(dataBytes("A:", "NTFS"), 0);

        final String rendered = response.toString();

        assertNotNull(rendered);
        assertTrue(rendered.startsWith("SmbComTreeConnectAndXResponse["), rendered);
        assertTrue(rendered.contains("supportSearchBits=true"), rendered);
        assertTrue(rendered.contains("shareIsInDfs=true"), rendered);
        assertTrue(rendered.contains("service=A:"), rendered);
        assertTrue(rendered.contains("nativeFileSystem=NTFS"), rendered);
        assertTrue(rendered.endsWith("]"), rendered);
    }
}
