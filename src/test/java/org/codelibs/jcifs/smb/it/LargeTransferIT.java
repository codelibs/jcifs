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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.Random;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.impl.SmbBufferSizeProbe;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.it.env.DialectMatrix;
import org.junit.jupiter.api.DisplayName;

/**
 * Reads and writes larger than 64 KiB.
 *
 * <p>
 * A multi-megabyte file round-trips whatever the transfer size is, because the streams chunk it - so moving the
 * payload proves nothing on its own. What these assert is the size the connection actually settled on: above 64 KiB
 * once multi-credit is negotiated, and exactly what it always was on SMB 2.0.2, which has no multi-credit and must
 * be left alone. The round trip on top of that is what shows the larger requests carry their data intact.
 * </p>
 */
class LargeTransferIT extends AbstractSmbIT {

    /** Several requests worth at a mebibyte each, and many more at the old 64 KiB. */
    private static final int PAYLOAD = 3 * 1024 * 1024;

    /** What the clamp produces without multi-credit: transaction_buf_size less the per-message overhead. */
    private static final int READ_SIZE_WITHOUT_MULTI_CREDIT = 64936;
    private static final int WRITE_SIZE_WITHOUT_MULTI_CREDIT = 64904;

    @DialectMatrix
    @DisplayName("a transfer above 64 KiB is negotiated from SMB 2.1 and carries its data intact")
    void largeTransferRoundTrips(final DialectVersion dialect) throws Exception {
        final CIFSContext context = contextFor(dialect);
        final SmbFile dir = createWorkDir(context, server().share());
        try {
            final byte[] payload = new byte[PAYLOAD];
            new Random(7).nextBytes(payload);

            final SmbFile file = new SmbFile(dir, "large-transfer.bin");
            try (OutputStream out = file.getOutputStream()) {
                out.write(payload);
            }

            final int readSize = SmbBufferSizeProbe.readSize(file);
            final int writeSize = SmbBufferSizeProbe.writeSize(file);
            if (dialect.atLeast(DialectVersion.SMB210)) {
                assertTrue(readSize > 65536, dialect + " should read in chunks larger than 64 KiB, negotiated " + readSize);
                assertTrue(writeSize > 65536, dialect + " should write in chunks larger than 64 KiB, negotiated " + writeSize);
            } else {
                assertEquals(READ_SIZE_WITHOUT_MULTI_CREDIT, readSize, "SMB 2.0.2 has no multi-credit, so its read size must not move");
                assertEquals(WRITE_SIZE_WITHOUT_MULTI_CREDIT, writeSize, "SMB 2.0.2 has no multi-credit, so its write size must not move");
            }

            final byte[] readBack = new byte[PAYLOAD];
            try (InputStream in = file.getInputStream()) {
                int off = 0;
                int n;
                while (off < PAYLOAD && (n = in.read(readBack, off, PAYLOAD - off)) > 0) {
                    off += n;
                }
                assertEquals(PAYLOAD, off, "the whole file should have been read back");
            }

            assertEquals(PAYLOAD, file.length(), "the file on the server should be the size that was written");
            assertArrayEquals(payload, readBack, "every byte should survive a transfer that spans several requests");
        } finally {
            deleteQuietly(dir);
        }
    }
}
