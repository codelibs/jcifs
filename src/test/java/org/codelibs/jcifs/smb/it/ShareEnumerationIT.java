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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.SmbResource;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.it.env.DialectMatrix;
import org.codelibs.jcifs.smb.it.env.RequiresDefaultPort;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Listing the shares a server offers.
 *
 * <p>
 * On SMB2 this is srvsvc NetShareEnum over the {@code IPC$} named pipe, with no
 * fallback: {@code SmbEnumerationUtil.doShareEnum} rethrows rather than dropping
 * to the SMB1 transaction. Every other test in the suite addresses a share
 * directly, so this is the only cover for the RPC path and for the
 * {@code TYPE_SERVER} branch of the locator.
 * </p>
 *
 * <p>
 * Server and workgroup enumeration - a URL with no host - is deliberately absent:
 * it is SMB1 only and throws {@code SmbUnsupportedOperationException} under the
 * SMB2 floor this suite negotiates.
 * </p>
 */
@RequiresDefaultPort
class ShareEnumerationIT extends AbstractSmbIT {

    /**
     * @return the share names the server reports, lower-cased and without the trailing separator
     */
    private Set<String> enumerateShares(final CIFSContext context) throws Exception {
        try (SmbFile root = new SmbFile("smb://" + server().host() + "/", context)) {
            return Arrays.stream(root.listFiles())
                    .map(SmbResource::getName)
                    .map(name -> name.endsWith("/") ? name.substring(0, name.length() - 1) : name)
                    .map(name -> name.toLowerCase(Locale.ROOT))
                    .collect(Collectors.toSet());
        }
    }

    @DialectMatrix
    @DisplayName("the server lists the shares the fixture defines")
    void serverListsTheFixtureShares(final DialectVersion dialect) throws Exception {
        final Set<String> shares = enumerateShares(contextFor(dialect));

        assertTrue(shares.contains(server().share()), "the plain share should be listed, got " + shares);
        assertTrue(shares.contains(server().encryptedShare()), "the encrypted share should be listed, got " + shares);
        assertTrue(shares.contains("users"), "the shared users share should be listed, got " + shares);
        assertTrue(shares.contains("testuser1private"), "a private share should still be listed, got " + shares);
    }

    @Test
    @DisplayName("the enumeration includes the IPC share it was fetched over")
    void enumerationIncludesIpc() throws Exception {
        final Set<String> shares = enumerateShares(server().context());
        assertTrue(shares.contains("ipc$"), "IPC$ should be listed, got " + shares);
    }

    @Test
    @DisplayName("a server URL reports itself as a server")
    void serverUrlReportsItselfAsAServer() throws Exception {
        try (SmbFile root = new SmbFile("smb://" + server().host() + "/", server().context())) {
            assertEquals(SmbConstants.TYPE_SERVER, root.getType(), "a host-only URL should report TYPE_SERVER");
        }
    }
}
