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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for the {@link SmbComNegotiate} class.
 */
public class SmbComNegotiateTest {

    private PropertyConfiguration config;

    @BeforeEach
    public void setUp() throws CIFSException {
        this.config = new PropertyConfiguration(new Properties());
    }

    private static PropertyConfiguration configWith(final String key, final String value) throws CIFSException {
        final Properties properties = new Properties();
        properties.setProperty(key, value);
        return new PropertyConfiguration(properties);
    }

    /**
     * Asserts that a single dialect entry sits at the given offset: the 0x02 buffer format byte,
     * the ASCII dialect name and the NUL terminator.
     *
     * @return the offset just past the entry
     */
    private static int assertDialectAt(final byte[] buffer, final int offset, final String dialect) {
        assertEquals(0x02, buffer[offset], "dialect entries start with buffer format 0x02");
        assertEquals(dialect, new String(buffer, offset + 1, dialect.length(), StandardCharsets.US_ASCII));
        assertEquals(0x00, buffer[offset + 1 + dialect.length()], "dialect names are NUL terminated");
        return offset + dialect.length() + 2;
    }

    @Test
    @DisplayName("The command is SMB_COM_NEGOTIATE")
    public void shouldUseNegotiateCommand() {
        assertEquals(ServerMessageBlock.SMB_COM_NEGOTIATE, new SmbComNegotiate(this.config, false).getCommand());
    }

    @Test
    @DisplayName("The constructor copies flags2 from the configuration")
    public void shouldTakeFlags2FromConfiguration() {
        assertEquals(this.config.getFlags2(), new SmbComNegotiate(this.config, false).getFlags2());
    }

    @Test
    @DisplayName("The signing enforced flag is reported back unchanged")
    public void shouldReportSigningEnforced() {
        assertTrue(new SmbComNegotiate(this.config, true).isSigningEnforced());
        assertFalse(new SmbComNegotiate(this.config, false).isSigningEnforced());
    }

    @Test
    @DisplayName("The request carries no parameter words")
    public void shouldWriteNoParameterWords() {
        final byte[] dst = new byte[8];

        assertEquals(0, new SmbComNegotiate(this.config, false).writeParameterWordsWireFormat(dst, 0));
        assertArrayEquals(new byte[8], dst);
    }

    @Test
    @DisplayName("An SMB1 only configuration offers just NT LM 0.12")
    public void shouldOfferOnlyTheSmb1Dialect() throws CIFSException {
        final SmbComNegotiate request = new SmbComNegotiate(configWith("jcifs.client.maxVersion", "SMB1"), false);
        final byte[] dst = new byte[64];

        final int written = request.writeBytesWireFormat(dst, 0);

        assertEquals(12, written);
        assertEquals(12, assertDialectAt(dst, 0, "NT LM 0.12"));
    }

    @Test
    @DisplayName("An SMB2 only configuration offers just the two SMB2 dialects")
    public void shouldOfferOnlyTheSmb2Dialects() throws CIFSException {
        final SmbComNegotiate request = new SmbComNegotiate(configWith("jcifs.client.minVersion", "SMB202"), false);
        final byte[] dst = new byte[64];

        final int written = request.writeBytesWireFormat(dst, 0);

        assertEquals(22, written);
        int offset = assertDialectAt(dst, 0, "SMB 2.???");
        offset = assertDialectAt(dst, offset, "SMB 2.002");
        assertEquals(22, offset);
    }

    @Test
    @DisplayName("The default configuration offers NT LM 0.12 followed by the two SMB2 dialects")
    public void shouldOfferAllThreeDialectsByDefault() {
        final SmbComNegotiate request = new SmbComNegotiate(this.config, false);
        final byte[] dst = new byte[64];

        final int written = request.writeBytesWireFormat(dst, 0);

        assertEquals(34, written);
        int offset = assertDialectAt(dst, 0, "NT LM 0.12");
        offset = assertDialectAt(dst, offset, "SMB 2.???");
        offset = assertDialectAt(dst, offset, "SMB 2.002");
        assertEquals(34, offset);
    }

    @Test
    @DisplayName("The dialect list is written at the requested offset")
    public void shouldWriteTheDialectsAtTheGivenOffset() throws CIFSException {
        final SmbComNegotiate request = new SmbComNegotiate(configWith("jcifs.client.maxVersion", "SMB1"), false);
        final byte[] dst = new byte[64];

        assertEquals(12, request.writeBytesWireFormat(dst, 7));

        assertEquals(12 + 7, assertDialectAt(dst, 7, "NT LM 0.12"));
        assertArrayEquals(new byte[7], java.util.Arrays.copyOfRange(dst, 0, 7), "nothing before the offset may be touched");
    }

    @Test
    @DisplayName("Decoding consumes no parameter words and no data bytes")
    public void shouldReadNothing() {
        final SmbComNegotiate request = new SmbComNegotiate(this.config, false);
        final byte[] buffer = new byte[] { 0x01, 0x02, 0x03, 0x04 };

        assertEquals(0, request.readParameterWordsWireFormat(buffer, 0));
        assertEquals(0, request.readBytesWireFormat(buffer, 0));
    }

    @Test
    @DisplayName("toString names the message and does not throw")
    public void shouldRenderToString() {
        final String rendered = new SmbComNegotiate(this.config, false).toString();

        assertNotNull(rendered);
        assertTrue(rendered.startsWith("SmbComNegotiate["), rendered);
        assertTrue(rendered.contains("dialects=NT LM 0.12"), rendered);
        assertTrue(rendered.endsWith("]"), rendered);
    }
}
