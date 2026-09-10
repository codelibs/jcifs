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
package org.codelibs.jcifs.smb.it.env;

/**
 * The SMB server implementation the integration tests are running against.
 *
 * <p>
 * Several behaviours are correct but different on each backend - Samba resolves
 * symlinks inside a share on the server, Windows hands the reparse point back to
 * the client - so tests that observe such a difference are written once per
 * backend and selected with {@link RequiresBackend} rather than branching
 * internally.
 * </p>
 */
public enum SmbBackend {

    /** Samba, either the container started by the harness or an external server. */
    SAMBA,

    /** A real Windows SMB server. */
    WINDOWS
}
