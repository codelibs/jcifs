import jcifs.smb.*;

public class SidLookup {

    public static void main(String[] argv) throws Exception {
        if (argv.length < 2) {
            System.err.println("usage: SidLookup dc1.busicorp.local S-1-5-21-1496946806-2192648263-3843101252-4321");
            return;
        }

        SID sid = new SID(argv[1]);
        sid.resolve(argv[0], null);
        System.out.println("      toString: " + sid.toString());
        System.out.println("   toSidString: " + sid.toDisplayString());
        System.out.println("       getType: " + sid.getType());
        System.out.println("   getTypeText: " + sid.getTypeText());
        System.out.println(" getDomainName: " + sid.getDomainName());
        System.out.println("getAccountName: " + sid.getAccountName());
    }
}
