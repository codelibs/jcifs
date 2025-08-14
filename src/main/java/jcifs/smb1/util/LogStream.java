/* jcifs smb client library in Java
 * Copyright (C) 2004  "Michael B. Allen" <jcifs at samba dot org>
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package jcifs.smb1.util;

import java.io.PrintStream;

/**
0 - nothing
1 - critical [default]
2 - basic info can be logged under load
3 - almost everything
N - debugging
 */

public class LogStream extends PrintStream {

    private static LogStream inst;

    public static int level = 1;

    public LogStream(final PrintStream stream) {
        super(stream);
    }

    public static void setLevel(final int level) {
        LogStream.level = level;
    }

    /**
     * This must be called before <code>getInstance</code> is called or
     * it will have no effect.
     */
    public static void setInstance(final PrintStream stream) {
        inst = new LogStream(stream);
    }

    public static LogStream getInstance() {
        if (inst == null) {
            setInstance(System.err);
        }
        return inst;
    }
}
