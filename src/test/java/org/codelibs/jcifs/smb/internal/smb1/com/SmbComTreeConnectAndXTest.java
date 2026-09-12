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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Properties;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.Credentials;
import org.codelibs.jcifs.smb.RuntimeCIFSException;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.impl.NtlmPasswordAuthenticator;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for the {@link SmbComTreeConnectAndX} class.
 *
 * <p>
 * The parameter words of an SMB_COM_TREE_CONNECT_ANDX request are Flags(2) and PasswordLength(2),
 * four bytes once the AndX bytes have been accounted for. The data bytes are the password, the NUL
 * terminated share path and the NUL terminated ASCII service string.
 * </p>
 */
public class SmbComTreeConnectAndXTest {

    private static final String PATH = "\\\\SERVER\\share";
    private static final String SERVICE = "A:";

    private PropertyConfiguration config;
    private CIFSContext context;

    @BeforeEach
    public void setUp() throws CIFSException {
        this.config = new PropertyConfiguration(new Properties());
        this.context = mock(CIFSContext.class);
        when(this.context.getConfig()).thenReturn(this.config);
    }

    private ServerData serverData(final int security, final boolean encryptedPasswords) {
        final ServerData server = new ServerData();
        server.security = security;
        server.encryptedPasswords = encryptedPasswords;
        server.encryptionKey = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        return server;
    }

    private SmbComTreeConnectAndX request(final ServerData server) {
        return new SmbComTreeConnectAndX(this.context, server, PATH, SERVICE, null);
    }

    @Test
    @DisplayName("The command is SMB_COM_TREE_CONNECT_ANDX")
    public void shouldUseTreeConnectAndXCommand() {
        when(this.context.getCredentials()).thenReturn(mock(Credentials.class));

        assertEquals(ServerMessageBlock.SMB_COM_TREE_CONNECT_ANDX, request(serverData(SmbConstants.SECURITY_USER, true)).getCommand());
    }

    @Test
    @DisplayName("A chained command is retained as the AndX of the request")
    public void shouldRetainTheChainedCommand() {
        final SmbComQueryInformation andx = new SmbComQueryInformation(this.config, PATH);

        assertSame(andx,
                new SmbComTreeConnectAndX(this.context, serverData(SmbConstants.SECURITY_USER, true), PATH, SERVICE, andx).getAndx());
    }

    @Test
    @DisplayName("User level security sends no password, only the one byte placeholder")
    public void shouldSendNoPasswordUnderUserSecurity() {
        when(this.context.getCredentials()).thenReturn(mock(Credentials.class));
        final SmbComTreeConnectAndX request = request(serverData(SmbConstants.SECURITY_USER, true));
        final byte[] dst = new byte[8];

        assertEquals(4, request.writeParameterWordsWireFormat(dst, 0));

        assertEquals(0x00, dst[0], "disconnectTid is always false");
        assertEquals(0x00, dst[1], "the second flags byte is reserved");
        assertEquals(1, SMBUtil.readInt2(dst, 2), "a single NUL byte stands in for the password");
    }

    @Test
    @DisplayName("Share level security with non NTLM credentials also falls back to the placeholder")
    public void shouldSendNoPasswordForNonNtlmCredentials() {
        when(this.context.getCredentials()).thenReturn(mock(Credentials.class));
        final SmbComTreeConnectAndX request = request(serverData(SmbConstants.SECURITY_SHARE, true));
        final byte[] dst = new byte[4];

        assertEquals(4, request.writeParameterWordsWireFormat(dst, 0));
        assertEquals(1, SMBUtil.readInt2(dst, 2));
    }

    @Test
    @DisplayName("The parameter words are written at the requested offset")
    public void shouldHonourTheWriteOffset() {
        when(this.context.getCredentials()).thenReturn(mock(Credentials.class));
        final SmbComTreeConnectAndX request = request(serverData(SmbConstants.SECURITY_USER, true));
        final byte[] dst = new byte[12];

        assertEquals(4, request.writeParameterWordsWireFormat(dst, 4));

        assertArrayEquals(new byte[4], Arrays.copyOfRange(dst, 0, 4), "nothing before the offset may be touched");
        assertEquals(1, SMBUtil.readInt2(dst, 6));
    }

    @Test
    @DisplayName("Share level security with an encrypted password sends the 24 byte LM response")
    public void shouldSendTheEncryptedPassword() {
        when(this.context.getCredentials()).thenReturn(new NtlmPasswordAuthenticator("DOMAIN", "user", "secret"));
        final SmbComTreeConnectAndX request = request(serverData(SmbConstants.SECURITY_SHARE, true));
        final byte[] parameterWords = new byte[4];

        assertEquals(4, request.writeParameterWordsWireFormat(parameterWords, 0));
        assertEquals(24, SMBUtil.readInt2(parameterWords, 2), "an LMv2 response is 24 bytes");

        request.setUseUnicode(false);
        final byte[] dst = new byte[64];
        final int written = request.writeBytesWireFormat(dst, 0);

        assertEquals(24 + PATH.length() + 1 + SERVICE.length() + 1, written);
        assertEquals(PATH, new String(dst, 24, PATH.length(), StandardCharsets.US_ASCII));
        assertEquals(0x00, dst[24 + PATH.length()]);
        assertEquals(SERVICE, new String(dst, 24 + PATH.length() + 1, SERVICE.length(), StandardCharsets.US_ASCII));
        assertEquals(0x00, dst[written - 1]);
    }

    @Test
    @DisplayName("Share level security with plain text passwords disabled is refused")
    public void shouldRefusePlainTextPasswords() {
        when(this.context.getCredentials()).thenReturn(new NtlmPasswordAuthenticator("DOMAIN", "user", "secret"));
        final SmbComTreeConnectAndX request = request(serverData(SmbConstants.SECURITY_SHARE, false));

        final RuntimeCIFSException thrown =
                assertThrows(RuntimeCIFSException.class, () -> request.writeParameterWordsWireFormat(new byte[4], 0));

        assertEquals("Plain text passwords are disabled", thrown.getMessage());
    }

    @Test
    @DisplayName("Share level security with plain text passwords enabled sends the password as a string")
    public void shouldSendAPlainTextPassword() throws CIFSException {
        final Properties properties = new Properties();
        properties.setProperty("jcifs.client.disablePlainTextPasswords", "false");
        final PropertyConfiguration plainTextConfig = new PropertyConfiguration(properties);
        when(this.context.getConfig()).thenReturn(plainTextConfig);
        when(this.context.getCredentials()).thenReturn(new NtlmPasswordAuthenticator("DOMAIN", "user", "pw"));

        final SmbComTreeConnectAndX request = request(serverData(SmbConstants.SECURITY_SHARE, false));
        request.setUseUnicode(false);
        final byte[] parameterWords = new byte[4];

        assertEquals(4, request.writeParameterWordsWireFormat(parameterWords, 0));

        // the password buffer is OEM encoded: two characters plus the NUL terminator
        assertEquals(3, SMBUtil.readInt2(parameterWords, 2));
    }

    @Test
    @DisplayName("The data bytes are the password placeholder, the share path and the service string")
    public void shouldWriteTheOemDataBytes() {
        when(this.context.getCredentials()).thenReturn(mock(Credentials.class));
        final SmbComTreeConnectAndX request = request(serverData(SmbConstants.SECURITY_USER, true));
        request.setUseUnicode(false);
        request.writeParameterWordsWireFormat(new byte[4], 0);
        final byte[] dst = new byte[64];

        final int written = request.writeBytesWireFormat(dst, 0);

        assertEquals(1 + PATH.length() + 1 + SERVICE.length() + 1, written);
        assertEquals(0x00, dst[0], "the password placeholder is a single NUL");
        assertEquals(PATH, new String(dst, 1, PATH.length(), StandardCharsets.US_ASCII));
        assertEquals(0x00, dst[1 + PATH.length()]);
        assertEquals(SERVICE, new String(dst, 2 + PATH.length(), SERVICE.length(), StandardCharsets.US_ASCII));
        assertEquals(0x00, dst[written - 1], "the service string is NUL terminated");
    }

    @Test
    @DisplayName("A Unicode share path is word aligned while the service string stays ASCII")
    public void shouldWriteAUnicodeSharePath() {
        when(this.context.getCredentials()).thenReturn(mock(Credentials.class));
        final SmbComTreeConnectAndX request =
                new SmbComTreeConnectAndX(this.context, serverData(SmbConstants.SECURITY_USER, true), "\\\\S\\a", SERVICE, null);
        request.setUseUnicode(true);
        request.writeParameterWordsWireFormat(new byte[4], 0);
        final byte[] dst = new byte[64];

        final int written = request.writeBytesWireFormat(dst, 0);

        // NUL password, alignment pad, five UTF-16LE characters, two byte terminator, "A:" and a NUL
        assertEquals(1 + 1 + 10 + 2 + 3, written);
        assertEquals(0x00, dst[0]);
        assertEquals(0x00, dst[1]);
        assertEquals("\\\\S\\a", new String(dst, 2, 10, StandardCharsets.UTF_16LE));
        assertEquals(SERVICE, new String(dst, 14, SERVICE.length(), StandardCharsets.US_ASCII));
        assertEquals(0x00, dst[16]);
    }

    @Test
    @DisplayName("Only the commands listed in the switch are batched")
    public void shouldBatchOnlyTheListedCommands() {
        when(this.context.getCredentials()).thenReturn(mock(Credentials.class));
        final SmbComTreeConnectAndX request = request(serverData(SmbConstants.SECURITY_USER, true));

        assertEquals(this.config.getBatchLimit("TreeConnectAndX.OpenAndX"),
                request.getBatchLimit(this.config, ServerMessageBlock.SMB_COM_OPEN_ANDX));
        assertEquals(this.config.getBatchLimit("TreeConnectAndX.QueryInformation"),
                request.getBatchLimit(this.config, ServerMessageBlock.SMB_COM_QUERY_INFORMATION));
        assertEquals(0, request.getBatchLimit(this.config, ServerMessageBlock.SMB_COM_CLOSE));
    }

    @Test
    @DisplayName("A request never decodes anything")
    public void shouldReadNothing() {
        when(this.context.getCredentials()).thenReturn(mock(Credentials.class));
        final SmbComTreeConnectAndX request = request(serverData(SmbConstants.SECURITY_USER, true));

        assertEquals(0, request.readParameterWordsWireFormat(new byte[32], 0));
        assertEquals(0, request.readBytesWireFormat(new byte[32], 0));
    }

    @Test
    @DisplayName("toString names the message and does not throw before or after encoding")
    public void shouldRenderToString() {
        when(this.context.getCredentials()).thenReturn(mock(Credentials.class));
        final SmbComTreeConnectAndX request = request(serverData(SmbConstants.SECURITY_USER, true));

        assertNotNull(request.toString(), "toString must survive an unencoded request whose password is still null");

        request.writeParameterWordsWireFormat(new byte[4], 0);
        final String rendered = request.toString();

        assertTrue(rendered.startsWith("SmbComTreeConnectAndX["), rendered);
        assertTrue(rendered.contains("passwordLength=1"), rendered);
        assertTrue(rendered.contains("path=" + PATH), rendered);
        assertTrue(rendered.contains("service=" + SERVICE), rendered);
        assertTrue(rendered.endsWith("]"), rendered);
    }
}
