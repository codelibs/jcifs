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

import org.codelibs.jcifs.smb.CIFSException;

/**
 * Test-only window onto the route {@code copyTo} will take for a pair of files.
 *
 * <p>
 * A copy produces the same bytes whether the server did it or the client streamed them, so no assertion on the
 * result can tell the two apart: a change that stopped routing copies to the server would leave every existing
 * copy test green. This asks the question that is otherwise invisible.
 * </p>
 *
 * <p>
 * Note precisely what it reports, and what it does not. It evaluates
 * {@link SmbCopyUtil#canServerSideCopy(SmbTreeHandleImpl, SmbTreeHandleImpl)} - the production predicate itself,
 * deliberately not a second copy of the same condition, which could agree with this probe while disagreeing with
 * the code that runs - so it reports the decision the copy will start from. It cannot report that the server
 * actually carried the copy out; a server free to refuse is then answered by falling back to streaming, and the
 * bytes are correct either way. What the copy produced is asserted separately.
 * </p>
 */
public final class SmbCopyUtilProbe {

    private SmbCopyUtilProbe() {
    }

    /**
     * Returns whether a copy from {@code src} to {@code dest} would be handed to the server.
     *
     * @param src  the source file
     * @param dest the destination file
     * @return whether the copy qualifies for FSCTL_SRV_COPYCHUNK
     * @throws CIFSException if either tree cannot be connected
     */
    public static boolean wouldCopyServerSide(final SmbFile src, final SmbFile dest) throws CIFSException {
        try (SmbTreeHandleImpl sh = src.ensureTreeConnected(); SmbTreeHandleImpl dh = dest.ensureTreeConnected()) {
            return SmbCopyUtil.canServerSideCopy(sh, dh);
        }
    }
}
