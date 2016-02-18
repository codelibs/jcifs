import jcifs.smb.SmbFileOutputStream;

public class SlowWrite {

    public static void main( String argv[] ) throws Exception {

        SmbFileOutputStream out = new SmbFileOutputStream( argv[0] );

        for( int i = 0; i < 2; i++ ) {
            out.write( (new String( "hello" + i )).getBytes() );
            Thread.sleep( 17000 );
        }

        out.close();
    }
}

