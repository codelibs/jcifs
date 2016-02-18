import jcifs.smb.SmbFile;
import jcifs.smb.SmbFileOutputStream;

public class OpenExclusive {

    public static void main( String argv[] ) throws Exception {
        SmbFileOutputStream out;
        SmbFile f = new SmbFile( argv[0], "", null, SmbFile.FILE_NO_SHARE );
        out = new SmbFileOutputStream( f );
System.in.read();
        out.close();
System.in.read();
// OR
        out = new SmbFileOutputStream( argv[1], SmbFile.FILE_NO_SHARE );
System.in.read();
        out.close();
System.in.read();
    }
}

