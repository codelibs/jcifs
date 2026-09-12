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

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * Restricts a test to a server reachable on the default SMB port.
 *
 * <p>
 * Some client paths build their own connection rather than reusing the one the
 * URL opened, and drop the port while doing so. Share enumeration is the case
 * this annotation exists for (issue #106): {@code SmbEnumerationUtil.getHandle} formats its
 * RPC binding from the host name alone, so against a server on a mapped port the
 * request goes to 445 on that host instead - a different server, or nothing at
 * all. Tests of those paths can only be trusted when the port is already 445.
 * </p>
 *
 * <p>
 * CI always qualifies: the Samba container is published on 445 on the Linux
 * runner and the Windows runner serves its own shares on 445. A developer
 * machine that is already sharing files does not, and there these tests skip.
 * </p>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.TYPE, ElementType.METHOD })
@ExtendWith(RequiresDefaultPort.Condition.class)
public @interface RequiresDefaultPort {

    /** Skips when the resolved server answers on any other port. */
    class Condition implements ExecutionCondition {

        /** The port an SMB URL omits. */
        private static final int DEFAULT_SMB_PORT = 445;

        @Override
        public ConditionEvaluationResult evaluateExecutionCondition(final ExtensionContext context) {
            final int port = SmbServerResolver.resolve().port();
            if (port == DEFAULT_SMB_PORT) {
                return ConditionEvaluationResult.enabled("server answers on the default SMB port");
            }
            return ConditionEvaluationResult.disabled("the server answers on port " + port
                    + " rather than 445, and the paths under test drop the port when they build their own connection");
        }
    }
}
