import jcifs.netbios.NbtAddress;
import jcifs.smb.SmbFile;
import java.util.Date;

public class ListFiles {

    public static void main( String[] argv ) throws Exception {

        for (int a = 0; a < argv.length; a++) {
            SmbFile file;
            SmbFile[] files = new SmbFile[0];

            file = new SmbFile( argv[a] );

            long t1 = System.currentTimeMillis();
            try {
                files = file.listFiles();
            } catch (Exception e) {
                e.printStackTrace();
            }
            long t2 = System.currentTimeMillis() - t1;

            for( int i = 0; i < files.length; i++ ) {
                System.out.print( " " + files[i].getName() );
            }
            System.out.println();
            System.out.println( files.length + " files in " + t2 + "ms" );
        }
    }
}
