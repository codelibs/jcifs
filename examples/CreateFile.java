import jcifs.smb.SmbFileOutputStream;

public class CreateFile {

    public static void main( String argv[] ) throws Exception {

        SmbFileOutputStream out = new SmbFileOutputStream( argv[0], false );
        out.close();
    }
}

