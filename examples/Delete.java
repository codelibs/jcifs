import jcifs.smb.*;

public class Delete {

    public static void main( String argv[] ) throws Exception {
        SmbFile f = new SmbFile( argv[0] );
        f.delete();
    }
}

