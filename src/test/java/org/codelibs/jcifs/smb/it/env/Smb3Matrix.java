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

import org.codelibs.jcifs.smb.DialectVersion;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Runs a test once per SMB3 dialect.
 *
 * <p>
 * SMB 3.0 introduced encryption and secure negotiation, 3.0.2 and 3.1.1 changed
 * how they are set up, and a feature can work on one of the three while being
 * broken on another. A test carrying this annotation takes the dialect as its
 * only parameter and is expected to build its context with
 * {@code AbstractSmbIT.contextFor(dialect)}.
 * </p>
 *
 * <p>
 * A test carrying this annotation chooses its own dialect and so ignores the
 * suite-wide {@code JCIFS_IT_DIALECT} pin. The {@link RequiresDialect} below
 * keeps the two coherent: a run pinned below SMB3 skips these sweeps rather
 * than quietly reaching past its own ceiling.
 * </p>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
@ParameterizedTest(name = "{0}")
@EnumSource(value = DialectVersion.class, names = { "SMB300", "SMB302", "SMB311" })
@RequiresDialect(DialectVersion.SMB300)
public @interface Smb3Matrix {
}
