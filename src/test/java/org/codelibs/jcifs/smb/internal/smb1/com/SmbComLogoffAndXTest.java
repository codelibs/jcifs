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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for the {@link SmbComLogoffAndX} class.
 */
public class SmbComLogoffAndXTest {

    private PropertyConfiguration config;

    @BeforeEach
    public void setUp() throws CIFSException {
        this.config = new PropertyConfiguration(new Properties());
    }

    @Test
    @DisplayName("The command is SMB_COM_LOGOFF_ANDX")
    public void shouldUseLogoffAndXCommand() {
        assertEquals(ServerMessageBlock.SMB_COM_LOGOFF_ANDX, new SmbComLogoffAndX(this.config, null).getCommand());
    }

    @Test
    @DisplayName("A chained command is retained as the AndX of the request")
    public void shouldRetainTheChainedCommand() {
        final SmbComTreeDisconnect andx = new SmbComTreeDisconnect(this.config);
        final SmbComLogoffAndX request = new SmbComLogoffAndX(this.config, andx);

        assertSame(andx, request.getAndx());
        assertSame(andx, request.getNext());
    }

    @Test
    @DisplayName("Without a chained command the AndX is absent")
    public void shouldHaveNoAndXWhenNoneIsGiven() {
        assertNull(new SmbComLogoffAndX(this.config, null).getAndx());
    }

    @Test
    @DisplayName("The request carries no parameter words")
    public void shouldWriteNoParameterWords() {
        final SmbComLogoffAndX request = new SmbComLogoffAndX(this.config, null);
        final byte[] dst = new byte[8];

        assertEquals(0, request.writeParameterWordsWireFormat(dst, 0));
        assertArrayEquals(new byte[8], dst, "no parameter word byte may be touched");
    }

    @Test
    @DisplayName("The request carries no data bytes")
    public void shouldWriteNoBytes() {
        final SmbComLogoffAndX request = new SmbComLogoffAndX(this.config, null);
        final byte[] dst = new byte[8];

        assertEquals(0, request.writeBytesWireFormat(dst, 0));
        assertArrayEquals(new byte[8], dst, "no data byte may be touched");
    }

    @Test
    @DisplayName("Decoding consumes no parameter words and no data bytes")
    public void shouldReadNothing() {
        final SmbComLogoffAndX request = new SmbComLogoffAndX(this.config, null);
        final byte[] buffer = new byte[] { 0x11, 0x22, 0x33, 0x44 };

        assertEquals(0, request.readParameterWordsWireFormat(buffer, 0));
        assertEquals(0, request.readBytesWireFormat(buffer, 0));
    }

    @Test
    @DisplayName("A non zero write offset is still honoured")
    public void shouldHonourTheWriteOffset() {
        final SmbComLogoffAndX request = new SmbComLogoffAndX(this.config, null);
        final byte[] dst = new byte[8];

        assertEquals(0, request.writeParameterWordsWireFormat(dst, 4));
        assertEquals(0, request.writeBytesWireFormat(dst, 4));
        assertArrayEquals(new byte[8], dst);
    }

    @Test
    @DisplayName("toString names the message and does not throw")
    public void shouldRenderToString() {
        final String rendered = new SmbComLogoffAndX(this.config, null).toString();

        assertNotNull(rendered);
        assertTrue(rendered.startsWith("SmbComLogoffAndX["), rendered);
        assertTrue(rendered.endsWith("]"), rendered);
    }
}
