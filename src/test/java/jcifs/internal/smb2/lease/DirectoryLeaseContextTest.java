/*
 * © 2025 CodeLibs, Inc.
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
package jcifs.internal.smb2.lease;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import jcifs.internal.util.SMBUtil;

/**
 * Unit tests for DirectoryLeaseContext
 */
public class DirectoryLeaseContextTest {

    @Test
    public void testConstructor() {
        Smb2LeaseKey key = new Smb2LeaseKey();
        int leaseState = DirectoryLeaseState.DIRECTORY_READ_HANDLE;
        DirectoryCacheScope scope = DirectoryCacheScope.IMMEDIATE_CHILDREN;

        DirectoryLeaseContext context = new DirectoryLeaseContext(key, leaseState, scope);

        assertEquals(key, context.getLeaseKey());
        assertEquals(leaseState, context.getLeaseState());
        assertEquals(scope, context.getCacheScope());
        assertEquals(30000L, context.getMaxCacheAge());
        assertTrue(context.isNotificationEnabled());
        assertEquals(0, context.getNotificationFilter());
    }

    @Test
    public void testGetName() {
        Smb2LeaseKey key = new Smb2LeaseKey();
        DirectoryLeaseContext context = new DirectoryLeaseContext(key, 0, DirectoryCacheScope.IMMEDIATE_CHILDREN);

        byte[] name = context.getName();
        assertNotNull(name);
        assertEquals("DLse", new String(name));
    }

    @Test
    public void testSettersAndGetters() {
        Smb2LeaseKey key1 = new Smb2LeaseKey();
        Smb2LeaseKey key2 = new Smb2LeaseKey();
        DirectoryLeaseContext context = new DirectoryLeaseContext(key1, 0, DirectoryCacheScope.IMMEDIATE_CHILDREN);

        context.setLeaseKey(key2);
        assertEquals(key2, context.getLeaseKey());

        context.setLeaseState(DirectoryLeaseState.DIRECTORY_FULL);
        assertEquals(DirectoryLeaseState.DIRECTORY_FULL, context.getLeaseState());

        context.setCacheScope(DirectoryCacheScope.RECURSIVE_TREE);
        assertEquals(DirectoryCacheScope.RECURSIVE_TREE, context.getCacheScope());

        context.setMaxCacheAge(60000L);
        assertEquals(60000L, context.getMaxCacheAge());

        context.setNotificationEnabled(false);
        assertFalse(context.isNotificationEnabled());

        context.setNotificationFilter(0xFF);
        assertEquals(0xFF, context.getNotificationFilter());
    }

    @Test
    public void testSize() {
        Smb2LeaseKey key = new Smb2LeaseKey();
        DirectoryLeaseContext context = new DirectoryLeaseContext(key, 0, DirectoryCacheScope.IMMEDIATE_CHILDREN);

        // Context header: 16 bytes
        // Name: 4 bytes ("DLse")
        // Padding: 4 bytes
        // Standard lease data: 32 bytes
        // Directory-specific data: 20 bytes
        assertEquals(76, context.size());
    }

    @Test
    public void testEncode() {
        Smb2LeaseKey key = new Smb2LeaseKey();
        int leaseState = DirectoryLeaseState.DIRECTORY_READ_HANDLE;
        DirectoryCacheScope scope = DirectoryCacheScope.RECURSIVE_TREE;

        DirectoryLeaseContext context = new DirectoryLeaseContext(key, leaseState, scope);
        context.setMaxCacheAge(45000L);
        context.setNotificationEnabled(true);
        context.setNotificationFilter(0x1F);

        byte[] buffer = new byte[context.size()];
        int bytesWritten = context.encode(buffer, 0);

        assertEquals(context.size(), bytesWritten);

        // Verify context header
        assertEquals(0, SMBUtil.readInt4(buffer, 0)); // Next
        assertEquals(16, SMBUtil.readInt2(buffer, 4)); // NameOffset
        assertEquals(4, SMBUtil.readInt2(buffer, 6)); // NameLength
        assertEquals(0, SMBUtil.readInt2(buffer, 8)); // Reserved
        assertEquals(24, SMBUtil.readInt2(buffer, 10)); // DataOffset
        assertEquals(52, SMBUtil.readInt4(buffer, 12)); // DataLength

        // Verify context name
        byte[] nameBytes = new byte[4];
        System.arraycopy(buffer, 16, nameBytes, 0, 4);
        assertEquals("DLse", new String(nameBytes));

        // Verify lease key (first 16 bytes of data)
        byte[] leaseKeyBytes = new byte[16];
        System.arraycopy(buffer, 24, leaseKeyBytes, 0, 16);
        assertArrayEquals(key.getKey(), leaseKeyBytes);

        // Verify lease state
        assertEquals(leaseState, SMBUtil.readInt4(buffer, 40));

        // Verify directory-specific data
        assertEquals(DirectoryCacheScope.RECURSIVE_TREE.ordinal(), SMBUtil.readInt4(buffer, 56)); // CacheScope
        assertEquals(45000L, SMBUtil.readInt8(buffer, 60)); // MaxCacheAge

        // Verify flags (RECURSIVE_TREE + NOTIFICATIONS)
        int expectedFlags = DirectoryLeaseContext.DIRECTORY_LEASE_FLAG_RECURSIVE | DirectoryLeaseContext.DIRECTORY_LEASE_FLAG_NOTIFICATIONS;
        assertEquals(expectedFlags, SMBUtil.readInt4(buffer, 68));

        // Verify notification filter
        assertEquals(0x1F, SMBUtil.readInt4(buffer, 72));
    }

    @Test
    public void testDecode() {
        // Create a context and encode it
        Smb2LeaseKey originalKey = new Smb2LeaseKey();
        int originalLeaseState = DirectoryLeaseState.DIRECTORY_FULL;
        DirectoryCacheScope originalScope = DirectoryCacheScope.METADATA_ONLY;

        DirectoryLeaseContext originalContext = new DirectoryLeaseContext(originalKey, originalLeaseState, originalScope);
        originalContext.setMaxCacheAge(60000L);
        originalContext.setNotificationEnabled(true);
        originalContext.setNotificationFilter(0x3F);

        byte[] buffer = new byte[originalContext.size()];
        originalContext.encode(buffer, 0);

        // Create a new context and decode
        DirectoryLeaseContext decodedContext = new DirectoryLeaseContext(new Smb2LeaseKey(), 0, DirectoryCacheScope.IMMEDIATE_CHILDREN);
        decodedContext.decode(buffer, 0, buffer.length);

        // Verify decoded values
        assertArrayEquals(originalKey.getKey(), decodedContext.getLeaseKey().getKey());
        assertEquals(originalLeaseState, decodedContext.getLeaseState());
        assertEquals(originalScope, decodedContext.getCacheScope());
        assertEquals(60000L, decodedContext.getMaxCacheAge());
        assertTrue(decodedContext.isNotificationEnabled());
        assertEquals(0x3F, decodedContext.getNotificationFilter());
    }

    @Test
    public void testDecodePartialData() {
        // Create a buffer with only standard lease data (no directory-specific data)
        byte[] buffer = new byte[56]; // Header + name + padding + standard lease data only

        // Write minimal header
        SMBUtil.writeInt4(0, buffer, 0); // Next
        SMBUtil.writeInt2(16, buffer, 4); // NameOffset
        SMBUtil.writeInt2(4, buffer, 6); // NameLength
        SMBUtil.writeInt2(0, buffer, 8); // Reserved
        SMBUtil.writeInt2(24, buffer, 10); // DataOffset
        SMBUtil.writeInt4(32, buffer, 12); // DataLength (standard lease only)

        // Write name
        System.arraycopy("DLse".getBytes(), 0, buffer, 16, 4);

        // Write lease key
        Smb2LeaseKey key = new Smb2LeaseKey();
        key.encode(buffer, 24);

        // Write lease state
        SMBUtil.writeInt4(DirectoryLeaseState.DIRECTORY_READ_HANDLE, buffer, 40);

        // Decode with partial data
        DirectoryLeaseContext context = new DirectoryLeaseContext(new Smb2LeaseKey(), 0, DirectoryCacheScope.IMMEDIATE_CHILDREN);
        context.decode(buffer, 0, 56);

        // Should decode standard lease data correctly
        assertArrayEquals(key.getKey(), context.getLeaseKey().getKey());
        assertEquals(DirectoryLeaseState.DIRECTORY_READ_HANDLE, context.getLeaseState());

        // Directory-specific fields should retain defaults
        assertEquals(DirectoryCacheScope.IMMEDIATE_CHILDREN, context.getCacheScope());
        assertEquals(30000L, context.getMaxCacheAge());
        assertTrue(context.isNotificationEnabled());
    }

    @Test
    public void testFlagsEncoding() {
        Smb2LeaseKey key = new Smb2LeaseKey();

        // Test with IMMEDIATE_CHILDREN scope (no recursive flag)
        DirectoryLeaseContext context1 = new DirectoryLeaseContext(key, 0, DirectoryCacheScope.IMMEDIATE_CHILDREN);
        context1.setNotificationEnabled(true);

        byte[] buffer1 = new byte[context1.size()];
        context1.encode(buffer1, 0);

        int flags1 = SMBUtil.readInt4(buffer1, 68);
        assertEquals(DirectoryLeaseContext.DIRECTORY_LEASE_FLAG_NOTIFICATIONS, flags1);

        // Test with RECURSIVE_TREE scope (recursive flag set)
        DirectoryLeaseContext context2 = new DirectoryLeaseContext(key, 0, DirectoryCacheScope.RECURSIVE_TREE);
        context2.setNotificationEnabled(true);

        byte[] buffer2 = new byte[context2.size()];
        context2.encode(buffer2, 0);

        int flags2 = SMBUtil.readInt4(buffer2, 68);
        assertEquals(DirectoryLeaseContext.DIRECTORY_LEASE_FLAG_RECURSIVE | DirectoryLeaseContext.DIRECTORY_LEASE_FLAG_NOTIFICATIONS,
                flags2);

        // Test with notifications disabled
        DirectoryLeaseContext context3 = new DirectoryLeaseContext(key, 0, DirectoryCacheScope.RECURSIVE_TREE);
        context3.setNotificationEnabled(false);

        byte[] buffer3 = new byte[context3.size()];
        context3.encode(buffer3, 0);

        int flags3 = SMBUtil.readInt4(buffer3, 68);
        assertEquals(DirectoryLeaseContext.DIRECTORY_LEASE_FLAG_RECURSIVE, flags3);
    }
}