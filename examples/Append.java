import jcifs.smb.SmbFile;
import jcifs.smb.SmbFileOutputStream;

public class Append {

    public static void main( String argv[] ) throws Exception {

        SmbFile f = new SmbFile( argv[0] );
        SmbFileOutputStream out = new SmbFileOutputStream( f, true );

        byte[] msg;
        int i = 0;
        while( i++ < 3 ) {
            msg = new String( "this is msg #" + i ).getBytes();
            out.write( msg );
            System.out.write( msg );
            Thread.sleep( 10000 );
//out = new SmbFileOutputStream( f, true );
        }

        out.close();
    }
}
