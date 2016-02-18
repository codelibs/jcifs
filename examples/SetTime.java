import jcifs.smb.SmbFile;
import jcifs.smb.SmbException;

public class SetTime {

    public static void main( String argv[] ) throws Exception {
        SmbFile f = new SmbFile( argv[0] );
        long time = f.getLastModified();
        f.setLastModified( time + 65000 ); /* add 1 minute and 5 seconds */
    }
}

