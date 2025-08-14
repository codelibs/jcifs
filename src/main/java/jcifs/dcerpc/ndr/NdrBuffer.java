/* jcifs msrpc client library in Java
 * Copyright (C) 2006  "Michael B. Allen" <jcifs at samba dot org>
 *                     "Eric Glass" <jcifs at samba dot org>
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

package jcifs.dcerpc.ndr;

import java.util.HashMap;
import java.util.Map;

import jcifs.util.Encdec;
import jcifs.util.Strings;

public class NdrBuffer {

    private int referent;
    private Map<Object, Entry> referents;

    private static class Entry {

        public Entry(final int referent, final Object obj) {
            this.referent = referent;
            this.obj = obj;
        }

        final int referent;

        @SuppressWarnings("unused")
        private final Object obj;
    }

    public byte[] buf;
    public int start;
    public int index;
    public int length;
    public NdrBuffer deferred;

    public NdrBuffer(final byte[] buf, final int start) {
        this.buf = buf;
        this.start = this.index = start;
        this.length = 0;
        this.deferred = this;
    }

    public NdrBuffer derive(final int idx) {
        final NdrBuffer nb = new NdrBuffer(this.buf, this.start);
        nb.index = idx;
        nb.deferred = this.deferred;
        return nb;
    }

    public void reset() {
        this.index = this.start;
        this.length = 0;
        this.deferred = this;
    }

    public int getIndex() {
        return this.index;
    }

    public void setIndex(final int index) {
        this.index = index;
    }

    public int getCapacity() {
        return this.buf.length - this.start;
    }

    public int getTailSpace() {
        return this.buf.length - this.index;
    }

    public byte[] getBuffer() {
        return this.buf;
    }

    public int align(final int boundary, final byte value) {
        final int n = align(boundary);
        int i = n;
        while (i > 0) {
            this.buf[this.index - i] = value;
            i--;
        }
        return n;
    }

    public void writeOctetArray(final byte[] b, final int i, final int l) {
        System.arraycopy(b, i, this.buf, this.index, l);
        advance(l);
    }

    public void readOctetArray(final byte[] b, final int i, final int l) {
        System.arraycopy(this.buf, this.index, b, i, l);
        advance(l);
    }

    public int getLength() {
        return this.deferred.length;
    }

    public void setLength(final int length) {
        this.deferred.length = length;
    }

    public void advance(final int n) {
        this.index += n;
        if (this.index - this.start > this.deferred.length) {
            this.deferred.length = this.index - this.start;
        }
    }

    public int align(final int boundary) {
        final int m = boundary - 1;
        final int i = this.index - this.start;
        final int n = (i + m & ~m) - i;
        advance(n);
        return n;
    }

    public void enc_ndr_small(final int s) {
        this.buf[this.index] = (byte) (s & 0xFF);
        advance(1);
    }

    public int dec_ndr_small() {
        final int val = this.buf[this.index] & 0xFF;
        advance(1);
        return val;
    }

    public void enc_ndr_short(final int s) {
        align(2);
        Encdec.enc_uint16le((short) s, this.buf, this.index);
        advance(2);
    }

    public int dec_ndr_short() {
        align(2);
        final int val = Encdec.dec_uint16le(this.buf, this.index);
        advance(2);
        return val;
    }

    public void enc_ndr_long(final int l) {
        align(4);
        Encdec.enc_uint32le(l, this.buf, this.index);
        advance(4);
    }

    public int dec_ndr_long() {
        align(4);
        final int val = Encdec.dec_uint32le(this.buf, this.index);
        advance(4);
        return val;
    }

    public void enc_ndr_hyper(final long h) {
        align(8);
        Encdec.enc_uint64le(h, this.buf, this.index);
        advance(8);
    }

    public long dec_ndr_hyper() {
        align(8);
        final long val = Encdec.dec_uint64le(this.buf, this.index);
        advance(8);
        return val;
    }

    /* float */
    /* double */
    public void enc_ndr_string(final String s) {
        align(4);
        int i = this.index;
        final int len = s.length();
        Encdec.enc_uint32le(len + 1, this.buf, i);
        i += 4;
        Encdec.enc_uint32le(0, this.buf, i);
        i += 4;
        Encdec.enc_uint32le(len + 1, this.buf, i);
        i += 4;
        System.arraycopy(Strings.getUNIBytes(s), 0, this.buf, i, len * 2);
        i += len * 2;
        this.buf[i] = (byte) '\0';
        i++;
        this.buf[i++] = (byte) '\0';
        advance(i - this.index);
    }

    public String dec_ndr_string() throws NdrException {
        align(4);
        int i = this.index;
        String val = null;
        int len = Encdec.dec_uint32le(this.buf, i);
        i += 12;
        if (len != 0) {
            len--;
            final int size = len * 2;
            if (size < 0 || size > 0xFFFF) {
                throw new NdrException(NdrException.INVALID_CONFORMANCE);
            }
            val = Strings.fromUNIBytes(this.buf, i, size);
            i += size + 2;
        }
        advance(i - this.index);
        return val;
    }

    private int getDceReferent(final Object obj) {
        Entry e;

        if (this.referents == null) {
            this.referents = new HashMap<>();
            this.referent = 1;
        }

        e = this.referents.get(obj);
        if (e == null) {
            e = new Entry(this.referent++, obj);
            this.referents.put(obj, e);
        }

        return e.referent;
    }

    public void enc_ndr_referent(final Object obj, final int type) {
        if (obj == null) {
            enc_ndr_long(0);
            return;
        }
        switch (type) {
        case 1: /* unique */
        case 3: /* ref */
            enc_ndr_long(System.identityHashCode(obj));
            return;
        case 2: /* ptr */
            enc_ndr_long(getDceReferent(obj));
        }
    }

    @Override
    public String toString() {
        return "start=" + this.start + ",index=" + this.index + ",length=" + getLength();
    }
}
