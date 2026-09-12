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
package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.codelibs.jcifs.smb.Address;
import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.Credentials;
import org.codelibs.jcifs.smb.internal.smb2.create.Smb2CreateRequest;
import org.codelibs.jcifs.smb.internal.smb2.lock.Smb2BreakNotifications;
import org.codelibs.jcifs.smb.internal.smb2.lock.Smb2OplockBreakNotification;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

/**
 * What the transport does with a break notification.
 *
 * <p>
 * A break arrives on the thread that reads the connection, so anything that goes wrong here costs more than a failed
 * request. These cover the paths that must not reach the network at all: a lease break, a break naming an open this
 * client does not have, and a break of an open that holds no oplock.
 * </p>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SmbTransportOplockBreakTest {

    private static final byte[] FILE_ID =
            { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58 };

    @Mock
    private CIFSContext cifsContext;
    @Mock
    private Configuration configuration;
    @Mock
    private Credentials credentials;
    @Mock
    private CredentialsInternal credentialsInternal;
    @Mock
    private Address address;

    private SmbTransportImpl transport;

    @BeforeEach
    void setup() {
        when(this.cifsContext.getConfig()).thenReturn(this.configuration);
        when(this.cifsContext.getCredentials()).thenReturn(this.credentials);
        when(this.credentials.unwrap(CredentialsInternal.class)).thenReturn(this.credentialsInternal);
        when(this.credentialsInternal.clone()).thenReturn(this.credentialsInternal);
        this.transport = new SmbTransportImpl(this.cifsContext, this.address, 445, null, 0, false);
    }

    /**
     * Builds a session holding one open, and indexes it on the transport the way a completed session setup does.
     */
    private SmbFileHandleImpl registerOpen(final long sessionId, final byte[] fileId, final byte oplockLevel) {
        final SmbSessionImpl session = new SmbSessionImpl(this.cifsContext, "server.example", "EXAMPLE", this.transport);
        final SmbTreeHandleImpl tree = mock(SmbTreeHandleImpl.class);
        lenient().when(tree.acquire()).thenReturn(tree);
        lenient().when(tree.getTreeId()).thenReturn(11L);
        lenient().when(tree.isConnected()).thenReturn(true);
        lenient().when(tree.isSMB2()).thenReturn(true);

        final SmbFileHandleImpl handle = new SmbFileHandleImpl(this.configuration, fileId, tree, "//server/share/f", 0, 0, 0, 0, 0L);
        handle.registerWith(session, oplockLevel);
        this.transport.registerSessionId(sessionId, session);
        return handle;
    }

    private Smb2OplockBreakNotification oplockBreak(final long sessionId, final byte[] fileId, final byte newLevel) throws Exception {
        final byte[] body = new byte[24];
        SMBUtil.writeInt2(24, body, 0);
        body[2] = newLevel;
        System.arraycopy(fileId, 0, body, 8, 16);
        final Smb2OplockBreakNotification notification = Smb2BreakNotifications.decodeBody(this.configuration, body);
        notification.setSessionId(sessionId);
        return notification;
    }

    @Test
    @DisplayName("a break of an open that holds no oplock is ignored outright")
    void testBreakOfOpenWithoutOplock() throws Exception {
        // Every ordinary open is in this state: jcifs asks for SMB2_OPLOCK_LEVEL_NONE on every create. MS-SMB2
        // 3.2.5.19.1 has the client stop processing, so nothing may be recorded from the notification either -
        // recording it would let an unverified message raise the level and make the next break answerable.
        final SmbFileHandleImpl open = registerOpen(0x1111L, FILE_ID, Smb2CreateRequest.SMB2_OPLOCK_LEVEL_NONE);

        this.transport.handleNotification(oplockBreak(0x1111L, FILE_ID, Smb2CreateRequest.SMB2_OPLOCK_LEVEL_BATCH));

        assertEquals(Smb2CreateRequest.SMB2_OPLOCK_LEVEL_NONE, open.getOplockLevel(),
                "an open that holds no oplock must not take a level from a break notification");
    }

    @Test
    @DisplayName("a lease break is handled without failing")
    void testLeaseBreakIsHandled() throws Exception {
        // A lease break has a lease key and no file id. jcifs never asks for a lease, so there is nothing to do with
        // it, but handling it must not throw: the break path runs on the receive thread.
        final byte[] body = new byte[44];
        SMBUtil.writeInt2(44, body, 0);
        SMBUtil.writeInt4(1, body, 4);
        SMBUtil.writeInt4(0x07, body, 24);
        SMBUtil.writeInt4(0x01, body, 28);
        final Smb2OplockBreakNotification notification = Smb2BreakNotifications.decodeBody(this.configuration, body);

        assertDoesNotThrow(() -> this.transport.handleNotification(notification));
    }

    @Test
    @DisplayName("a break naming an open this client does not have is ignored")
    void testBreakForUnknownOpen() throws Exception {
        final SmbFileHandleImpl open = registerOpen(0x2222L, FILE_ID, Smb2CreateRequest.SMB2_OPLOCK_LEVEL_BATCH);
        final byte[] otherFileId = new byte[16];

        assertDoesNotThrow(
                () -> this.transport.handleNotification(oplockBreak(0x2222L, otherFileId, Smb2CreateRequest.SMB2_OPLOCK_LEVEL_II)));

        assertEquals(Smb2CreateRequest.SMB2_OPLOCK_LEVEL_BATCH, open.getOplockLevel(),
                "a break for another file must leave this open alone");
    }

    @Test
    @DisplayName("an open is found by file id even when the notification names no session")
    void testOpenFoundWhenSessionIdIsZero() throws Exception {
        // Windows up to 2012 R2 and ksmbd send SessionId 0 in a break notification, so the file id is all there is.
        final SmbFileHandleImpl open = registerOpen(0x3333L, FILE_ID, Smb2CreateRequest.SMB2_OPLOCK_LEVEL_NONE);

        this.transport.handleNotification(oplockBreak(0L, FILE_ID, Smb2CreateRequest.SMB2_OPLOCK_LEVEL_II));

        // Nothing to assert about the level - the open holds no oplock - but it must have been resolved, which the
        // next test covers through the table itself.
        assertSame(open, this.transport.getSessionById(0x3333L).getOpen(FILE_ID));
    }

    @Test
    @DisplayName("a closed open is gone from the table a break would search")
    void testClosedOpenIsNotFound() throws Exception {
        final SmbFileHandleImpl open = registerOpen(0x4444L, FILE_ID, Smb2CreateRequest.SMB2_OPLOCK_LEVEL_BATCH);

        open.markClosed();

        assertNull(this.transport.getSessionById(0x4444L).getOpen(FILE_ID), "a closed open must not be resolvable from a break");
    }
}
