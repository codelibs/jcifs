import jcifs.smb.SmbFile;

public class RenameTo {

    public static void main( String argv[] ) throws Exception {

        SmbFile from = new SmbFile( argv[0] );
        SmbFile to = new SmbFile( argv[1] );
        from.renameTo( to );
    }
}

