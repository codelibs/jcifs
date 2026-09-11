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

import java.util.Properties;

import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.codelibs.jcifs.smb.impl.SmbNegotiationProbe;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Dialect negotiation against a real server.
 */
class DialectNegotiationIT extends AbstractSmbIT {

    @ParameterizedTest
    @EnumSource(value = DialectVersion.class, names = { "SMB202", "SMB210", "SMB300", "SMB302", "SMB311" })
    @DisplayName("the negotiated dialect is the configured maximum")
    void negotiatesTheConfiguredMaximum(final DialectVersion maximum) throws Exception {
        final Properties props = new Properties();
        props.setProperty("jcifs.client.maxVersion", maximum.name());
        try (SmbFile file = new SmbFile(server().url(server().share()), server().context(props))) {
            assertEquals(maximum, SmbNegotiationProbe.negotiatedDialect(file), "server should have accepted the client's maximum dialect");
        }
    }

    @Test
    @DisplayName("the default configuration reaches SMB 3.1.1")
    void defaultConfigurationReachesSmb311() throws Exception {
        try (SmbFile file = new SmbFile(server().url(server().share()), server().context())) {
            assertEquals(DialectVersion.SMB311, SmbNegotiationProbe.negotiatedDialect(file));
        }
    }

    @Test
    @DisplayName("a raised minimum still negotiates within the allowed range")
    void raisedMinimumStaysWithinRange() throws Exception {
        final Properties props = new Properties();
        props.setProperty("jcifs.client.minVersion", "SMB300");
        props.setProperty("jcifs.client.maxVersion", "SMB311");
        try (SmbFile file = new SmbFile(server().url(server().share()), server().context(props))) {
            final DialectVersion negotiated = SmbNegotiationProbe.negotiatedDialect(file);
            assertTrue(negotiated.atLeast(DialectVersion.SMB300), "negotiated " + negotiated + " below the configured minimum");
        }
    }
}
