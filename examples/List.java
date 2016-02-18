import jcifs.netbios.NbtAddress;
import jcifs.smb.SmbFile;
import java.util.Date;

public class List {

    public static void main( String[] argv ) throws Exception {

        SmbFile file = new SmbFile( argv[0] );

        long t1 = System.currentTimeMillis();
        String[] files = file.list();
        long t2 = System.currentTimeMillis() - t1;

        for( int i = 0; i < files.length; i++ ) {
            System.out.print( " " + files[i] );
        }
        System.out.println();
        System.out.println( files.length + " files in " + t2 + "ms" );
    }
}
