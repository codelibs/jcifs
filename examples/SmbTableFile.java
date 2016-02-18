/* jcifs smb client library in Java
 * Copyright (C) 2003  "Michael B. Allen" <jcifs at samba dot org>
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

import jcifs.smb.*;
import java.io.*;

public class SmbTableFile extends SmbRandomAccessFile {

    static final byte BYTE_FULL = (byte)0xFF;

    byte[] hdr = new byte[512];
    byte[] buf = new byte[1024];
    char[] cbuf = new char[512];
    int recordSize, row;

    public SmbTableFile( SmbFile file, String mode, int recordSize ) throws IOException {
        super( file, mode );
        this.recordSize = recordSize;
        read( hdr, 0, 512 );
    }
    public SmbTableFile( String url, String mode, int shareAccess, int recordSize ) throws IOException {
        super( url, mode, shareAccess );
        this.recordSize = recordSize;
        read( hdr, 0, 512 );
    }

    public void insert( SmbTableFileRecord tfr ) throws IOException {
        int i, b = 0;

        /* Find an unset bit it in the bitmap
         */
        for( i = 128; i < 512; i++ ) {
            if( hdr[i] != BYTE_FULL ) {
                /* bitwise complement inverts each bit
                 * mask with 0xFF ensures we only use 8 bits of int b
                 */
                b = ~hdr[i] & 0xFF;
                /* clever trick to isolate first bit on
                 */
                b = b & -b;
                break;
            }
        }
        if( i == 512 ) {
            throw new IOException( "No more space in " + this );
        }
        /* convert power of two to position
         */
        switch( b ) {
            case 1: b = 0; break;
            case 2: b = 1; break;
            case 4: b = 2; break;
            case 8: b = 3; break;
            case 16: b = 4; break;
            case 32: b = 5; break;
            case 64: b = 6; break;
            case 128: b = 7; break;
        }
        tfr.rowid = (i - 128) * 8 + b;
        update( tfr );
    }
    public void update( SmbTableFileRecord tfr ) throws IOException {
        int i;

        seek( 512L + tfr.rowid * recordSize );
        tfr.encode( this );

        i = 128 + tfr.rowid / 8;
        seek( i );
        hdr[i] |= 1 << (tfr.rowid % 8);
        write( hdr[i] );
    }
    public void get( SmbTableFileRecord tfr ) throws IOException {
        seek( 512L + tfr.rowid * recordSize );
        tfr.decode( this );
    }
    public void iterate() {
        row = 0;
    }
    public boolean next( SmbTableFileRecord tfr ) throws IOException {
        int i, b;

        i = 128 + row / 8;       /* Search bitmap for next bit that is on */
        b = 1 << (row % 8);
        for( ; i < 512; i++ ) {
            if(( hdr[i] & -b ) != 0 ) {
                b = hdr[i] & -b;
                b = b & -b;
                break;
            }
            b = 1;
        }
        if( i == 512 ) {                   /* Are no more on bits, return */
            return false;
        }
        switch( b ) {
            case 1: b = 0; break;
            case 2: b = 1; break;
            case 4: b = 2; break;
            case 8: b = 3; break;
            case 16: b = 4; break;
            case 32: b = 5; break;
            case 64: b = 6; break;
            case 128: b = 7; break;
        }
        tfr.rowid = (i - 128) * 8 + b;               /* Set rowid and get */
        get( tfr );

        row = tfr.rowid + 1;               /* Iterate row for next caller */

        return true;
    }
}
