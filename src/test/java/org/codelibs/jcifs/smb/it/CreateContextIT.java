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
package org.codelibs.jcifs.smb.it;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.impl.SmbCreateContextProbe;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.internal.smb2.create.CreateContextRequest;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Sends SMB2 CREATE requests carrying create contexts to a real server.
 *
 * <p>
 * A server that cannot parse the create context list refuses the request with
 * STATUS_INVALID_PARAMETER, and one given a broken {@code Next} chain only sees
 * the first context. Asking for two contexts that every server answers catches
 * both: each of them has to come back. The two orders cover a context with data
 * and one without in either position.
 * </p>
 */
class CreateContextIT extends AbstractSmbIT {

    private static final int SMB2_HEADER_LENGTH = 64;

    private SmbFile workDir;

    @AfterEach
    void removeWorkDir() {
        deleteQuietly(this.workDir);
    }

    @Test
    @DisplayName("every create context is answered when the first one carries data")
    void contextWithDataFirst() throws Exception {
        assertAnswered(open(maximalAccess(), queryOnDiskId()));
    }

    @Test
    @DisplayName("every create context is answered when the first one carries no data")
    void contextWithoutDataFirst() throws Exception {
        assertAnswered(open(queryOnDiskId(), maximalAccess()));
    }

    private Map<String, byte[]> open(final CreateContextRequest... contexts) throws Exception {
        final CIFSContext context = server().context();
        this.workDir = createWorkDir(context, server().share());
        final SmbFile file = writeFile(this.workDir, "contexts.txt", "create context target");
        return responseContexts(SmbCreateContextProbe.openWithContexts(file, contexts));
    }

    private static void assertAnswered(final Map<String, byte[]> answered) {
        final byte[] maximalAccess = answered.get("MxAc");
        assertNotNull(maximalAccess, "no maximal access response among " + answered.keySet());
        assertEquals(8, maximalAccess.length, "SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE length");
        assertEquals(0, SMBUtil.readInt4(maximalAccess, 0), "QueryStatus");
        assertTrue((SMBUtil.readInt4(maximalAccess, 4) & SmbConstants.FILE_READ_ATTRIBUTES) != 0,
                "the file's creator should have at least FILE_READ_ATTRIBUTES");

        final byte[] onDiskId = answered.get("QFid");
        assertNotNull(onDiskId, "no on-disk id response among " + answered.keySet());
        assertEquals(32, onDiskId.length, "SMB2_CREATE_QUERY_ON_DISK_ID response length");
    }

    /**
     * Walks the create contexts of a raw CREATE response independently of the
     * client's own decoder.
     */
    private static Map<String, byte[]> responseContexts(final byte[] response) {
        // CreateContextsOffset and CreateContextsLength are 80 and 84 bytes into the CREATE response body
        final long offset = SMBUtil.readInt4(response, SMB2_HEADER_LENGTH + 80) & 0xFFFFFFFFL;
        final long length = SMBUtil.readInt4(response, SMB2_HEADER_LENGTH + 84) & 0xFFFFFFFFL;
        final Map<String, byte[]> contexts = new LinkedHashMap<>();
        if (offset == 0 || length == 0) {
            return contexts;
        }
        // Every read stays inside CreateContextsLength, so a truncated or malformed list fails rather than reading zeros
        final long end = offset + length;
        assertTrue(end <= response.length, "the create contexts run past the end of the response");
        long start = offset;
        while (true) {
            assertTrue(start + 16 <= end, "a create context header runs past CreateContextsLength");
            final int at = (int) start;
            final long next = SMBUtil.readInt4(response, at) & 0xFFFFFFFFL;
            final int nameOffset = SMBUtil.readInt2(response, at + 4);
            final int nameLength = SMBUtil.readInt2(response, at + 6);
            final int dataOffset = SMBUtil.readInt2(response, at + 10);
            final long dataLength = SMBUtil.readInt4(response, at + 12) & 0xFFFFFFFFL;
            assertTrue(start + nameOffset + nameLength <= end && start + dataOffset + dataLength <= end,
                    "a create context runs past CreateContextsLength");
            final String name = new String(response, at + nameOffset, nameLength, StandardCharsets.US_ASCII);
            contexts.put(name, Arrays.copyOfRange(response, at + dataOffset, at + dataOffset + (int) dataLength));
            if (next == 0) {
                return contexts;
            }
            assertTrue(next >= 16 && next % 8 == 0, "invalid Next " + next);
            start += next;
        }
    }

    /**
     * @return SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST with a zero Timestamp, which
     *         never matches the file's last write time and so is always answered
     */
    private static CreateContextRequest maximalAccess() {
        return new FixedCreateContext("MxAc", new byte[8]);
    }

    /**
     * @return SMB2_CREATE_QUERY_ON_DISK_ID, which carries no data
     */
    private static CreateContextRequest queryOnDiskId() {
        return new FixedCreateContext("QFid", new byte[0]);
    }

    private static final class FixedCreateContext implements CreateContextRequest {

        private final byte[] name;
        private final byte[] data;

        FixedCreateContext(final String name, final byte[] data) {
            this.name = name.getBytes(StandardCharsets.US_ASCII);
            this.data = data;
        }

        @Override
        public byte[] getName() {
            return this.name;
        }

        @Override
        public int encode(final byte[] dst, final int dstIndex) {
            System.arraycopy(this.data, 0, dst, dstIndex, this.data.length);
            return this.data.length;
        }

        @Override
        public int size() {
            return this.data.length;
        }
    }
}
