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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for the {@link SmbComSessionSetupAndXResponse} class.
 *
 * <p>
 * The parameter words of an SMB_COM_SESSION_SETUP_ANDX response are Action(2), followed by
 * SecurityBlobLength(2) only when extended security was negotiated. The data bytes hold the
 * security blob, then NativeOS and NativeLanMan, and PrimaryDomain as well when extended security
 * was not negotiated.
 * </p>
 */
public class SmbComSessionSetupAndXResponseTest {

    private PropertyConfiguration config;

    @BeforeEach
    public void setUp() throws CIFSException {
        this.config = new PropertyConfiguration(new Properties());
    }

    private SmbComSessionSetupAndXResponse response(final boolean unicode, final boolean extendedSecurity) {
        final SmbComSessionSetupAndXResponse response = new SmbComSessionSetupAndXResponse(this.config, null);
        response.setUseUnicode(unicode);
        response.setExtendedSecurity(extendedSecurity);
        return response;
    }

    /** Concatenates NUL terminated OEM strings and leaves four spare bytes at the end. */
    private static byte[] oemStrings(final String... values) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (final String value : values) {
            out.writeBytes(value.getBytes(StandardCharsets.US_ASCII));
            out.write(0x00);
        }
        out.writeBytes(new byte[4]);
        return out.toByteArray();
    }

    /** Concatenates NUL terminated UTF-16LE strings and leaves four spare bytes at the end. */
    private static byte[] unicodeStrings(final String... values) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (final String value : values) {
            out.writeBytes(value.getBytes(StandardCharsets.UTF_16LE));
            out.write(0x00);
            out.write(0x00);
        }
        out.writeBytes(new byte[4]);
        return out.toByteArray();
    }

    @Test
    @DisplayName("A response accepts the session setup AndX command code")
    public void shouldCarryTheSessionSetupAndXCommand() {
        final SmbComSessionSetupAndXResponse response = new SmbComSessionSetupAndXResponse(this.config, null);

        assertEquals(0, response.getCommand(), "a bare response has no command until it is decoded");

        response.setCommand(ServerMessageBlock.SMB_COM_SESSION_SETUP_ANDX);
        assertEquals(ServerMessageBlock.SMB_COM_SESSION_SETUP_ANDX, response.getCommand());
    }

    @Test
    @DisplayName("A fresh response reports empty strings and no security blob")
    public void shouldStartEmpty() {
        final SmbComSessionSetupAndXResponse response = new SmbComSessionSetupAndXResponse(this.config, null);

        assertEquals("", response.getNativeOs());
        assertEquals("", response.getNativeLanMan());
        assertEquals("", response.getPrimaryDomain());
        assertNull(response.getBlob());
        assertFalse(response.isLoggedInAsGuest());
    }

    @Test
    @DisplayName("Without extended security the parameter words are just the two byte Action field")
    public void shouldDecodeTheActionFieldOnly() {
        final SmbComSessionSetupAndXResponse response = response(false, false);

        assertEquals(2, response.readParameterWordsWireFormat(new byte[] { 0x00, 0x00 }, 0));

        assertFalse(response.isLoggedInAsGuest());
        assertNull(response.getBlob(), "no blob is allocated without extended security");
    }

    @Test
    @DisplayName("Bit zero of the Action field is the guest login flag")
    public void shouldDecodeTheGuestFlag() {
        assertTrue(guestFlagOf((byte) 0x01));
        assertTrue(guestFlagOf((byte) 0x03), "the other Action bits are ignored");
        assertFalse(guestFlagOf((byte) 0x00));
        assertFalse(guestFlagOf((byte) 0x02));
        assertFalse(guestFlagOf((byte) 0xFE));
    }

    private boolean guestFlagOf(final byte action) {
        final SmbComSessionSetupAndXResponse response = response(false, false);
        response.readParameterWordsWireFormat(new byte[] { action, 0x00 }, 0);
        return response.isLoggedInAsGuest();
    }

    @Test
    @DisplayName("With extended security the parameter words also carry the security blob length")
    public void shouldDecodeTheBlobLength() {
        final byte[] buffer = new byte[8];
        buffer[2] = 0x01;
        SMBUtil.writeInt2(5, buffer, 4);

        final SmbComSessionSetupAndXResponse response = response(false, true);
        assertEquals(4, response.readParameterWordsWireFormat(buffer, 2));

        assertTrue(response.isLoggedInAsGuest());
        assertNotNull(response.getBlob());
        assertEquals(5, response.getBlob().length);
    }

    @Test
    @DisplayName("A zero length security blob is still allocated")
    public void shouldDecodeAnEmptyBlobLength() {
        final SmbComSessionSetupAndXResponse response = response(false, true);

        assertEquals(4, response.readParameterWordsWireFormat(new byte[4], 0));

        assertNotNull(response.getBlob());
        assertEquals(0, response.getBlob().length);
    }

    @Test
    @DisplayName("Without extended security the data bytes hold three OEM strings")
    public void shouldDecodeThreeOemStrings() {
        final byte[] buffer = oemStrings("Windows 5.1", "Windows 2000 LAN Manager", "WORKGROUP");
        final SmbComSessionSetupAndXResponse response = response(false, false);

        final int read = response.readBytesWireFormat(buffer, 0);

        assertEquals("Windows 5.1", response.getNativeOs());
        assertEquals("Windows 2000 LAN Manager", response.getNativeLanMan());
        assertEquals("WORKGROUP", response.getPrimaryDomain());
        assertEquals(12 + 25 + 10, read, "each OEM string costs its length plus a NUL");
    }

    @Test
    @DisplayName("Without extended security the data bytes hold three Unicode strings")
    public void shouldDecodeThreeUnicodeStrings() {
        final byte[] buffer = unicodeStrings("Win", "LM", "DOM");
        final SmbComSessionSetupAndXResponse response = response(true, false);

        final int read = response.readBytesWireFormat(buffer, 0);

        assertEquals("Win", response.getNativeOs());
        assertEquals("LM", response.getNativeLanMan());
        assertEquals("DOM", response.getPrimaryDomain());
        assertEquals(8 + 6 + 8, read, "each Unicode string costs twice its length plus a two byte terminator");
    }

    @Test
    @DisplayName("With extended security the blob comes first and no primary domain follows")
    public void shouldDecodeTheBlobAndTwoStrings() {
        final byte[] blob = { (byte) 0x60, (byte) 0x40, (byte) 0x06, (byte) 0x2B };
        final byte[] tail = oemStrings("Windows 6.1", "Windows 6.1");
        final byte[] buffer = new byte[blob.length + tail.length];
        System.arraycopy(blob, 0, buffer, 0, blob.length);
        System.arraycopy(tail, 0, buffer, blob.length, tail.length);

        final SmbComSessionSetupAndXResponse response = response(false, true);
        final byte[] parameterWords = new byte[4];
        SMBUtil.writeInt2(blob.length, parameterWords, 2);
        assertEquals(4, response.readParameterWordsWireFormat(parameterWords, 0));

        final int read = response.readBytesWireFormat(buffer, 0);

        assertArrayEquals(blob, response.getBlob());
        assertEquals("Windows 6.1", response.getNativeOs());
        assertEquals("Windows 6.1", response.getNativeLanMan());
        assertEquals("", response.getPrimaryDomain(), "extended security responses carry no primary domain");
        assertEquals(blob.length + 12 + 12, read);
    }

    @Test
    @DisplayName("Empty OEM strings are decoded as empty and cost one byte each")
    public void shouldDecodeEmptyStrings() {
        final SmbComSessionSetupAndXResponse response = response(false, false);

        final int read = response.readBytesWireFormat(oemStrings("", "", ""), 0);

        assertEquals("", response.getNativeOs());
        assertEquals("", response.getNativeLanMan());
        assertEquals("", response.getPrimaryDomain());
        assertEquals(3, read);
    }

    @Test
    @DisplayName("A response never encodes anything")
    public void shouldNotEncodeAnything() {
        final SmbComSessionSetupAndXResponse response = new SmbComSessionSetupAndXResponse(this.config, null);
        final byte[] dst = new byte[16];

        assertEquals(0, response.writeParameterWordsWireFormat(dst, 0));
        assertEquals(0, response.writeBytesWireFormat(dst, 0));
        assertArrayEquals(new byte[16], dst);
    }

    @Test
    @DisplayName("toString names the message and does not throw")
    public void shouldRenderToString() {
        final SmbComSessionSetupAndXResponse response = response(false, false);
        response.readParameterWordsWireFormat(new byte[] { 0x01, 0x00 }, 0);
        response.readBytesWireFormat(oemStrings("Unix", "Samba", "WORKGROUP"), 0);

        final String rendered = response.toString();

        assertNotNull(rendered);
        assertTrue(rendered.startsWith("SmbComSessionSetupAndXResponse["), rendered);
        assertTrue(rendered.contains("isLoggedInAsGuest=true"), rendered);
        assertTrue(rendered.contains("nativeOs=Unix"), rendered);
        assertTrue(rendered.contains("primaryDomain=WORKGROUP"), rendered);
        assertTrue(rendered.endsWith("]"), rendered);
    }
}
