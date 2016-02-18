import jcifs.smb.*;

public class TestRandomAccess {

    public static class TestRecord extends SmbTableFileRecord {

        boolean f1; /* 1 byte */
        byte f2;    /* 1 byte */
        int f3;     /* 1 byte */
        short f4;   /* 2 bytes */
        int f5;     /* 2 bytes */
        char f6;    /* 2 bytes */
        int f7;     /* 4 bytes */
        long f8;    /* 8 bytes */
        float f9;   /* 4 bytes */
        double f10; /* 8 bytes */
        String f11; /* 95 bytes max */
                    /* 128 bytes total */

        public TestRecord() {
        }
        public TestRecord( boolean f1, byte f2, int f3, short f4,
                int f5, char f6, int f7, long f8,
                float f9, double f10, String f11 ) {
            this.f1 = f1;
            this.f2 = f2;
            this.f3 = f3;
            this.f4 = f4;
            this.f5 = f5;
            this.f6 = f6;
            this.f7 = f7;
            this.f8 = f8;
            this.f9 = f9;
            this.f10 = f10;
            this.f11 = f11;
        }

        public void encode( SmbTableFile tf ) throws SmbException {
            tf.writeBoolean( f1 );
            tf.writeByte( f2 );
            tf.writeByte( f3 );
            tf.writeShort( f4 );
            tf.writeShort( f5 );
            tf.writeChar( f6 );
            tf.writeInt( f7 );
            tf.writeLong( f8 );
            tf.writeFloat( f9 );
            tf.writeDouble( f10 );
            tf.writeUTF( f11 );
        }
        public void decode( SmbTableFile tf ) throws SmbException {
            f1 = tf.readBoolean();
            f2 = tf.readByte();
            f3 = tf.readUnsignedByte();
            f4 = tf.readShort();
            f5 = tf.readUnsignedShort();
            f6 = tf.readChar();
            f7 = tf.readInt();
            f8 = tf.readLong();
            f9 = tf.readFloat();
            f10 = tf.readDouble();
            f11 = tf.readUTF();
        }
        public boolean equals( Object obj ) {
            if( obj instanceof TestRecord ) {
                TestRecord r = (TestRecord)obj;

                return r.f1 == f1 &&
                    r.f2 == f2 &&
                    r.f3 == f3 &&
                    r.f4 == f4 &&
                    r.f5 == f5 &&
                    r.f6 == f6 &&
                    r.f7 == f7 &&
                    r.f8 == f8 &&
                    r.f9 == f9 &&
                    r.f10 == f10 &&
                    f11.equals( r.f11 );
            }
            return false;
        }
    }

    public static void main( String[] argv ) throws Exception {
        if( argv.length < 2 ) {
            System.err.println( "usage: TestRandomAccess <url> <N> (1 for read or 2 for write with <index>)" );
            return;
        }
        SmbTableFile stf;
        int op = Integer.parseInt( argv[1] );

        TestRecord r1 = new TestRecord( true, (byte)0x12, 0x34, (short)0x1122,
                    0x3344, '\u04c1', 0x11112222, 0x1111111122222222L,
                    0.1122f, 3344.1, "The surface is smooth like glass" );

        if( op == 3 ) {
            stf = new SmbTableFile( argv[0], "rw", 0, 128 );
            int newLength = Integer.parseInt( argv[2] );
            stf.setLength( newLength );
            System.out.println( "truncated to " + newLength );
        } else if( op == 1 ) {
            SmbFile file = new SmbFile( argv[0], null, SmbFile.FILE_SHARE_READ );
            stf = new SmbTableFile( file, "rw", 128 );
            stf.insert( r1 );
            System.out.println( "rowid: " + r1.rowid );
        } else {
            if( argv.length < 3 ) {
                System.err.println( "usage: TestRandomAccess <url> <N> (1 for read or 2 for write with <index>)" );
                return;
            }
            stf = new SmbTableFile( argv[0], "r", 0, 128 );
            TestRecord r2 = new TestRecord();
            r2.rowid = Integer.parseInt( argv[2] );
            stf.get( r2 );
            System.out.println( "r1.equals( r2 ) = " + r1.equals( r2 ));
        }

        stf.close();
    }
}

