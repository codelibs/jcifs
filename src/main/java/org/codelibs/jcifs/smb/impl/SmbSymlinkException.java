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

import org.codelibs.jcifs.smb.internal.smb2.Smb2SymlinkErrorResponse;

/**
 * Thrown when a server answers STATUS_STOPPED_ON_SYMLINK, meaning the path traverses a symbolic link
 * that the server will not follow on the client's behalf.
 *
 * <p>
 * jCIFS does not resolve symbolic links, so the operation fails. This exception carries the link
 * target the server disclosed, letting callers report or follow it themselves. Being an
 * {@link SmbException}, it is still caught by existing handlers, and {@link #getNtStatus()} still
 * returns STATUS_STOPPED_ON_SYMLINK.
 * </p>
 *
 * <p>
 * Beware that the target is the server's own view of the link. A relative target
 * ({@link #isRelative()}) is relative to the directory holding the link; an absolute one is
 * expressed in the server's namespace and need not be reachable through this share at all.
 * </p>
 */
public class SmbSymlinkException extends SmbException {

    private static final long serialVersionUID = 1L;

    /** The path that was requested when the server stopped on the link, or null if unknown. */
    private final String path;

    /** The link target as the server stores it. */
    private final String substituteName;

    /** The link target in display form. */
    private final String printName;

    /** Whether the target is relative to the directory holding the link. */
    private final boolean relative;

    /** UTF-16 byte count of the requested path the server had not consumed. */
    private final int unparsedPathLength;

    SmbSymlinkException(final String path, final Smb2SymlinkErrorResponse symlink) {
        super(NtStatus.NT_STATUS_STOPPED_ON_SYMLINK, null);
        this.path = path;
        this.substituteName = symlink.getSubstituteName();
        this.printName = symlink.getPrintName();
        this.relative = symlink.isRelative();
        this.unparsedPathLength = symlink.getUnparsedPathLength();
    }

    @Override
    public String getMessage() {
        return super.getMessage() + " " + (this.path != null ? this.path : "The path") + " points to "
                + (this.relative ? "the relative target " : "the absolute target ") + '"' + this.substituteName + '"'
                + ", which jCIFS does not resolve.";
    }

    /**
     * Returns the path that was requested when the server stopped on the link, if known.
     *
     * @return the requested path, or null
     */
    public String getPath() {
        return this.path;
    }

    /**
     * Returns the link target as the server stores it. This is the name to resolve against, and is
     * interpreted according to {@link #isRelative()}.
     *
     * @return the substitute name
     */
    public String getSubstituteName() {
        return this.substituteName;
    }

    /**
     * Returns the link target in a form meant for display, which may differ from the substitute name
     * and is not suitable for resolution.
     *
     * @return the print name
     */
    public String getPrintName() {
        return this.printName;
    }

    /**
     * Whether the target is relative to the directory containing the link. An absolute target is
     * expressed in the server's own namespace, in forms such as {@code \??\C:\...} on Windows, and
     * is not necessarily reachable through this share.
     *
     * @return true if the target is relative
     */
    public boolean isRelative() {
        return this.relative;
    }

    /**
     * Returns how many bytes at the end of the requested path the server had not consumed when it
     * hit the link, as a UTF-16 byte count. Resolving the link means substituting the target for
     * everything ahead of that tail.
     *
     * @return the unparsed path length in bytes
     */
    public int getUnparsedPathLength() {
        return this.unparsedPathLength;
    }
}
