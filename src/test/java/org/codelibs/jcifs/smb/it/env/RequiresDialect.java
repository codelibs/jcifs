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
import java.util.Optional;

import org.codelibs.jcifs.smb.DialectVersion;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.platform.commons.support.AnnotationSupport;

/**
 * Restricts a test to a run whose dialect ceiling reaches the given version.
 *
 * <p>
 * The suite normally negotiates the highest dialect both ends support, so this
 * annotation is a no-op. It matters when the whole suite is pinned to one
 * dialect with {@code JCIFS_IT_DIALECT}: a test of an SMB3-only feature such as
 * encryption cannot pass under an SMB 2.0.2 pin, and skipping is the honest
 * answer rather than failing.
 * </p>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.TYPE, ElementType.METHOD })
@ExtendWith(RequiresDialect.Condition.class)
public @interface RequiresDialect {

    /**
     * @return the lowest dialect the test needs the run to be able to reach
     */
    DialectVersion value();

    /** Skips when the run is pinned below the required dialect. */
    class Condition implements ExecutionCondition {

        @Override
        public ConditionEvaluationResult evaluateExecutionCondition(final ExtensionContext context) {
            final Optional<RequiresDialect> annotation = AnnotationSupport.findAnnotation(context.getElement(), RequiresDialect.class);
            if (annotation.isEmpty()) {
                return ConditionEvaluationResult.enabled("no dialect requirement");
            }
            final DialectVersion required = annotation.get().value();
            final DialectVersion ceiling = SmbServerResolver.resolve().dialectCeiling();
            if (ceiling.atLeast(required)) {
                return ConditionEvaluationResult.enabled("the run can reach " + ceiling);
            }
            return ConditionEvaluationResult.disabled("requires " + required + " but the run is pinned to " + ceiling);
        }
    }
}
