import jcifs.smb.SmbFile;
import jcifs.smb.SmbFileOutputStream;
import java.io.FileInputStream;

public class GrowWrite {

    static final int SIZE = 0xFFF;

    public static void main( String argv[] ) throws Exception {
        int n, tot;
        byte[] buf = new byte[SIZE];
        SmbFile f = new SmbFile( argv[0] );
        SmbFileOutputStream out = new SmbFileOutputStream( f );

        n = tot = 0;
        do {
            if(( n % 0x1F ) == 0) {
                f = new SmbFile( argv[0] );
                out = new SmbFileOutputStream( f );
                System.out.print( '#' );
            }
            out.write( buf, 0, n );
            out.flush();
            tot += n;
        } while( n++ < SIZE );

        System.out.println();
        System.out.println( tot + " bytes transfered." );
    }
}
