import jcifs.smb.SmbFile;
import jcifs.smb.SmbFileInputStream;
import java.io.FileOutputStream;

public class Get {

    public static void main( String argv[] ) throws Exception {

        SmbFile f = new SmbFile( argv[0] );
        SmbFileInputStream in = new SmbFileInputStream( f );
        FileOutputStream out = new FileOutputStream( f.getName() );

        long t0 = System.currentTimeMillis();

        byte[] b = new byte[8192];
        int n, tot = 0;
        long t1 = t0;
        while(( n = in.read( b )) > 0 ) {
            out.write( b, 0, n );
            tot += n;
            System.out.print( '#' );
        }

        long t = System.currentTimeMillis() - t0;

        System.out.println();
        System.out.println( tot + " bytes transfered in " + ( t / 1000 ) + " seconds at " + (( tot / 1000 ) / Math.max( 1, ( t / 1000 ))) + "Kbytes/sec" );

        in.close();
        out.close();
    }
}

