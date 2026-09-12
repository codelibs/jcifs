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
 * Runs a test once per SMB2 and SMB3 dialect.
 *
 * <p>
 * Use this where the behaviour under test is expected to hold all the way down
 * to SMB 2.0.2; use {@link Smb3Matrix} where the feature only exists in SMB3.
 * SMB1 is deliberately absent: the integration suite negotiates SMB2 upwards,
 * and SMB1 is covered by the unit tests.
 * </p>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
@ParameterizedTest(name = "{0}")
@EnumSource(value = DialectVersion.class, names = { "SMB202", "SMB210", "SMB300", "SMB302", "SMB311" })
public @interface DialectMatrix {
}
