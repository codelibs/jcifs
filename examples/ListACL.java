import jcifs.smb.*;

public class ListACL {

    public static void main( String[] args ) throws Exception {
        if (args.length < 1) {
            System.err.println( "usage: ListACL <smburl>\n" );
            return;
        }
        SmbFile f = new SmbFile( args[0] );
        ACE[] acl = f.getSecurity();
        for (int i = 0; i < acl.length; i++) {
            System.out.println( acl[i] );
            SID sid = acl[i].getSID();
            System.out.println("      toString: " + sid.toString());
            System.out.println("   toSidString: " + sid.toDisplayString());
            System.out.println("       getType: " + sid.getType());
            System.out.println("   getTypeText: " + sid.getTypeText());
            System.out.println(" getDomainName: " + sid.getDomainName());
            System.out.println("getAccountName: " + sid.getAccountName());
        }
    }
}
