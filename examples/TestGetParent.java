import jcifs.smb.SmbFile;

public class TestGetParent
{

    public static void main( String argv[] ) throws Exception
    {
        if( argv.length < 1 ) {
            throw new IllegalArgumentException( "smb:// URL is required" );
        }

        SmbFile f = new SmbFile(argv[0]);

        System.out.println("  getPath: " + f.getPath());
        System.out.println("getParent: " + f.getParent());
    }
}
