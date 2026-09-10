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

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.it.env.SmbServerExtension;
import org.codelibs.jcifs.smb.it.env.SmbServerFixture;
import org.codelibs.jcifs.smb.it.env.SmbServerResolver;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base class for the SMB integration tests.
 *
 * <p>
 * Extending this class is what connects a test to the resolved backend and to
 * the preflight checks; it deliberately carries no assertions of its own.
 * </p>
 */
@ExtendWith(SmbServerExtension.class)
public abstract class AbstractSmbIT {

    private static final Logger log = LoggerFactory.getLogger(AbstractSmbIT.class);

    /**
     * @return the resolved server
     */
    protected static SmbServerFixture server() {
        return SmbServerResolver.resolve();
    }

    /**
     * Creates an empty directory unique to the calling test.
     *
     * @param context   the context to create it with
     * @param shareName the share to create it in
     * @return the created directory, which the caller is responsible for removing
     * @throws Exception if the directory cannot be created
     */
    protected SmbFile createWorkDir(final CIFSContext context, final String shareName) throws Exception {
        final SmbFile dir = new SmbFile(server().url(shareName, "it-" + UUID.randomUUID() + "/"), context);
        dir.mkdirs();
        return dir;
    }

    /**
     * Writes a small text file.
     *
     * @param parent   the directory to write into
     * @param name     the file name
     * @param contents the contents to write
     * @return the written file
     * @throws Exception if the file cannot be written
     */
    protected SmbFile writeFile(final SmbFile parent, final String name, final String contents) throws Exception {
        final SmbFile file = new SmbFile(parent, name);
        try (OutputStream out = file.getOutputStream()) {
            out.write(contents.getBytes(StandardCharsets.UTF_8));
        }
        return file;
    }

    /**
     * Removes a directory tree, ignoring anything that has already gone.
     *
     * @param file the root of the tree to remove
     */
    protected void deleteQuietly(final SmbFile file) {
        if (file == null) {
            return;
        }
        try {
            if (file.exists()) {
                file.delete();
            }
        } catch (final Exception e) {
            log.debug("Ignoring cleanup failure for {}", file, e);
        }
    }
}
