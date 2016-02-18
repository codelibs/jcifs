import jcifs.smb.*;

public class GetSecurity {

    public static void main( String[] argv ) throws Exception {

        SmbFile file = new SmbFile( argv[0] );
        ACE[] security = file.getSecurity(true);

        for (int ai = 0; ai < security.length; ai++) {
            System.out.println(security[ai].toString());
        }
    }
}
