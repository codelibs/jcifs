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

import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * Resolves the SMB server once per JVM and runs the preflight checks before any
 * integration test executes.
 */
public class SmbServerExtension implements BeforeAllCallback {

    private static volatile boolean checked;
    private static volatile RuntimeException failure;

    @Override
    public void beforeAll(final ExtensionContext context) throws Exception {
        final SmbServerFixture fixture = SmbServerResolver.resolve();
        if (checked) {
            if (failure != null) {
                throw failure;
            }
            return;
        }
        synchronized (SmbServerExtension.class) {
            if (checked) {
                if (failure != null) {
                    throw failure;
                }
                return;
            }
            try {
                SmbItPreflight.check(fixture);
            } catch (final RuntimeException e) {
                failure = e;
                throw e;
            } catch (final Exception e) {
                failure = new IllegalStateException("SMB integration test preflight failed", e);
                throw failure;
            } finally {
                checked = true;
            }
        }
    }
}
