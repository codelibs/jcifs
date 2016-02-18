import jcifs.smb.SmbFile;

public class AllocInfo {

    public static void main( String argv[] ) throws Exception {

        SmbFile f = new SmbFile( argv[0] );
        System.out.println( f.getDiskFreeSpace() );
    }
}

