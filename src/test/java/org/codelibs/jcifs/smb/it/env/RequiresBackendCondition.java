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

import java.util.Optional;

import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.platform.commons.support.AnnotationSupport;

/**
 * Evaluates {@link RequiresBackend} against the backend the harness resolved.
 */
public class RequiresBackendCondition implements ExecutionCondition {

    @Override
    public ConditionEvaluationResult evaluateExecutionCondition(final ExtensionContext context) {
        final Optional<RequiresBackend> annotation = AnnotationSupport.findAnnotation(context.getElement(), RequiresBackend.class);
        if (annotation.isEmpty()) {
            return ConditionEvaluationResult.enabled("no backend requirement");
        }
        final SmbBackend required = annotation.get().value();
        final SmbBackend actual = SmbServerResolver.resolve().backend();
        if (required == actual) {
            return ConditionEvaluationResult.enabled("running against " + actual);
        }
        return ConditionEvaluationResult.disabled("requires the " + required + " backend, running against " + actual);
    }
}
