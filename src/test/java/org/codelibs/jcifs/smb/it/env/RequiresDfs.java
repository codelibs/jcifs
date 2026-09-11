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
 * Restricts a test to a server that can serve DFS referrals.
 *
 * <p>
 * A referral names a host but no port, so only a server reachable on 445
 * qualifies. CI hosts have 445 free; a developer machine that is sharing files
 * does not, and there these tests skip. When {@code JCIFS_IT_REQUIRED=true} the
 * preflight refuses to start at all rather than let them skip unnoticed.
 * </p>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.TYPE, ElementType.METHOD })
@ExtendWith(RequiresDfs.Condition.class)
public @interface RequiresDfs {

    /** Skips when the resolved server cannot serve referrals. */
    class Condition implements ExecutionCondition {

        @Override
        public ConditionEvaluationResult evaluateExecutionCondition(final ExtensionContext context) {
            final SmbServerFixture fixture = SmbServerResolver.resolve();
            if (fixture.dfsAvailable()) {
                return ConditionEvaluationResult.enabled("server is reachable on the default SMB port");
            }
            return ConditionEvaluationResult
                    .disabled("DFS referrals cannot be followed: the server answers on port " + fixture.port() + " rather than 445");
        }
    }
}
