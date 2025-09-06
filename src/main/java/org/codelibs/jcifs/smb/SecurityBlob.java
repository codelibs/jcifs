/*
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
package org.codelibs.jcifs.smb;

/**
 * This class represents the Secrity_Blob in SMB Block and is set to support
 * kerberos authentication.
 *
 * @author Shun
 *
 */
class SecurityBlob {

    private byte[] b = {};

    SecurityBlob() {
    }

    SecurityBlob(final byte[] b) {
        set(b);
    }

    void set(final byte[] b) {
        this.b = b == null ? new byte[0] : b;
    }

    byte[] get() {
        return this.b;
    }

    int length() {
        if (this.b == null) {
            return 0;
        }
        return this.b.length;
    }

    /*
     * (non-Javadoc)
     *
     * @see java.lang.Object#clone()
     */
    @Override
    protected Object clone() throws CloneNotSupportedException {
        return new SecurityBlob(this.b.clone());
    }

    /*
     * (non-Javadoc)
     *
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object arg0) {
        try {
            final SecurityBlob t = (SecurityBlob) arg0;
            for (int i = 0; i < this.b.length; i++) {
                if (this.b[i] != t.b[i]) {
                    return false;
                }
            }
            return true;
        } catch (final Throwable e) {
            return false;
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return this.b.hashCode();
    }

    /*
     * (non-Javadoc)
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        StringBuilder ret = new StringBuilder();
        for (final byte element : this.b) {
            final int n = element & 0xff;
            if (n <= 0x0f) {
                ret.append("0");
            }
            ret.append(Integer.toHexString(n));
        }
        return ret.toString();
    }
}
