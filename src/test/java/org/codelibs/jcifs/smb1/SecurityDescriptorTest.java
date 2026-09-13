package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Decoding the security descriptor a server returns for a file.
 *
 * <p>
 * A crawler sorts the SID of every ACE into an allowed or a denied set by {@link ACE#isAllow()}, and reads the owner
 * from a descriptor it asked for with only the owner requested. The descriptors here are laid out byte by byte in the
 * self-relative form of MS-DTYP 2.4.6, so the decoder is checked against the wire format rather than against an
 * encoder of its own.
 * </p>
 */
class SecurityDescriptorTest {

    static final int SE_DACL_PRESENT = 0x0004;
    static final int SE_SELF_RELATIVE = 0x8000;

    /** ACCESS_ALLOWED_ACE_TYPE */
    static final int ALLOWED = 0x00;
    /** ACCESS_DENIED_ACE_TYPE */
    static final int DENIED = 0x01;

    static final String OWNER = "S-1-5-21-1-2-3-1001";
    static final String GROUP = "S-1-5-21-1-2-3-513";
    static final String ADMINISTRATORS = "S-1-5-32-544";
    static final String EVERYONE = "S-1-1-0";

    static byte[] sid(final String textual) {
        final String[] parts = textual.split("-");
        final int subAuthorities = parts.length - 3;
        final ByteBuffer buffer = ByteBuffer.allocate(8 + 4 * subAuthorities).order(ByteOrder.LITTLE_ENDIAN);
        buffer.put((byte) Integer.parseInt(parts[1])).put((byte) subAuthorities);
        // The authority is six bytes, big-endian, unlike everything around it.
        final long authority = Long.parseLong(parts[2]);
        for (int shift = 40; shift >= 0; shift -= 8) {
            buffer.put((byte) (authority >>> shift));
        }
        for (int i = 3; i < parts.length; i++) {
            buffer.putInt((int) Long.parseLong(parts[i]));
        }
        return buffer.array();
    }

    static byte[] ace(final int type, final int flags, final int mask, final String sid) {
        final byte[] sidBytes = sid(sid);
        return ByteBuffer.allocate(8 + sidBytes.length)
                .order(ByteOrder.LITTLE_ENDIAN)
                .put((byte) type)
                .put((byte) flags)
                .putShort((short) (8 + sidBytes.length))
                .putInt(mask)
                .put(sidBytes)
                .array();
    }

    static byte[] acl(final byte[]... aces) {
        int size = 8;
        for (final byte[] ace : aces) {
            size += ace.length;
        }
        final ByteBuffer buffer = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
        buffer.put((byte) 2).put((byte) 0).putShort((short) size).putShort((short) aces.length).putShort((short) 0);
        for (final byte[] ace : aces) {
            buffer.put(ace);
        }
        return buffer.array();
    }

    /**
     * A self-relative descriptor: the header, then the owner, the group and the DACL in that order. A null part is
     * left out and its offset written as zero.
     */
    static byte[] descriptor(final String owner, final String group, final byte[] dacl) {
        final byte[] ownerBytes = owner == null ? new byte[0] : sid(owner);
        final byte[] groupBytes = group == null ? new byte[0] : sid(group);
        final byte[] daclBytes = dacl == null ? new byte[0] : dacl;
        final int ownerOffset = owner == null ? 0 : 20;
        final int groupOffset = group == null ? 0 : 20 + ownerBytes.length;
        final int daclOffset = dacl == null ? 0 : 20 + ownerBytes.length + groupBytes.length;
        final int control = SE_SELF_RELATIVE | (dacl == null ? 0 : SE_DACL_PRESENT);
        return ByteBuffer.allocate(20 + ownerBytes.length + groupBytes.length + daclBytes.length)
                .order(ByteOrder.LITTLE_ENDIAN)
                .put((byte) 1)
                .put((byte) 0)
                .putShort((short) control)
                .putInt(ownerOffset)
                .putInt(groupOffset)
                .putInt(0)
                .putInt(daclOffset)
                .put(ownerBytes)
                .put(groupBytes)
                .put(daclBytes)
                .array();
    }

    @Test
    @DisplayName("the owner, the group and every ACE of the DACL are decoded")
    void decodesOwnerGroupAndDacl() throws Exception {
        final byte[] wire = descriptor(OWNER, GROUP,
                acl(ace(ALLOWED, ACE.FLAGS_OBJECT_INHERIT | ACE.FLAGS_CONTAINER_INHERIT | ACE.FLAGS_INHERITED, 0x001F01FF, ADMINISTRATORS),
                        ace(DENIED, 0, ACE.FILE_READ_DATA, OWNER), ace(ALLOWED, 0, 0x001200A9, EVERYONE)));

        final SecurityDescriptor sd = new SecurityDescriptor();
        final int consumed = sd.decode(wire, 0, wire.length);

        assertEquals(wire.length, consumed);
        assertEquals(SE_SELF_RELATIVE | SE_DACL_PRESENT, sd.type);
        assertEquals(OWNER, sd.owner_user.toString());
        assertEquals(GROUP, sd.owner_group.toString());
        assertEquals(3, sd.aces.length);

        assertTrue(sd.aces[0].isAllow());
        assertTrue(sd.aces[0].isInherited());
        assertEquals(0x001F01FF, sd.aces[0].getAccessMask());
        assertEquals(ADMINISTRATORS, sd.aces[0].getSID().toString());
        assertEquals("This folder, subfolders and files", sd.aces[0].getApplyToText());

        assertFalse(sd.aces[1].isAllow(), "an ACCESS_DENIED ACE must not be reported as allowing access");
        assertFalse(sd.aces[1].isInherited());
        assertEquals(ACE.FILE_READ_DATA, sd.aces[1].getAccessMask());
        assertEquals(OWNER, sd.aces[1].getSID().toString());

        assertTrue(sd.aces[2].isAllow());
        assertEquals(0x001200A9, sd.aces[2].getAccessMask());
        assertEquals(EVERYONE, sd.aces[2].getSID().toString());
    }

    @Test
    @DisplayName("a descriptor that starts part-way into a buffer is decoded from its own offsets")
    void decodesFromAnOffset() throws Exception {
        final byte[] descriptor = descriptor(OWNER, GROUP, acl(ace(DENIED, 0, ACE.FILE_READ_DATA, OWNER)));
        final byte[] buffer = new byte[11 + descriptor.length];
        System.arraycopy(descriptor, 0, buffer, 11, descriptor.length);

        final SecurityDescriptor sd = new SecurityDescriptor(buffer, 11, descriptor.length);

        assertEquals(OWNER, sd.owner_user.toString());
        assertEquals(GROUP, sd.owner_group.toString());
        assertEquals(1, sd.aces.length);
        assertFalse(sd.aces[0].isAllow());
    }

    @Test
    @DisplayName("a descriptor asked for the owner alone carries the owner and no DACL")
    void ownerOnlyDescriptor() throws Exception {
        final byte[] wire = descriptor(OWNER, null, null);

        final SecurityDescriptor sd = new SecurityDescriptor(wire, 0, wire.length);

        assertEquals(OWNER, sd.owner_user.toString());
        assertNull(sd.owner_group);
        assertNull(sd.aces, "a missing DACL is reported as null, not as an empty list");
    }

    @Test
    @DisplayName("an empty DACL is decoded as an empty list")
    void emptyDacl() throws Exception {
        final byte[] wire = descriptor(OWNER, GROUP, acl());

        final SecurityDescriptor sd = new SecurityDescriptor(wire, 0, wire.length);

        assertEquals(0, sd.aces.length);
    }

    @Test
    @DisplayName("a DACL claiming more than 4096 ACEs is refused")
    void oversizedDaclIsRefused() {
        final byte[] header = ByteBuffer.allocate(8)
                .order(ByteOrder.LITTLE_ENDIAN)
                .put((byte) 2)
                .put((byte) 0)
                .putShort((short) 8)
                .putShort((short) 4097)
                .putShort((short) 0)
                .array();
        final byte[] wire = descriptor(null, null, header);

        assertThrows(IOException.class, () -> new SecurityDescriptor(wire, 0, wire.length));
    }
}
