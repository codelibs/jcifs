import jcifs.smb.SmbFile;
import jcifs.smb.SmbFileInputStream;
import java.io.FileOutputStream;

public class SlowRead {

    public static void main( String argv[] ) throws Exception {

        SmbFileInputStream in = new SmbFileInputStream( argv[0] );

        byte[] b = new byte[10];
        int n, tot = 0;
        while(( n = in.read( b )) > 0 ) {
            System.out.write( b, 0, n );
            tot += n;
            Thread.sleep( 10000 );
        }

        in.close();
    }
}

