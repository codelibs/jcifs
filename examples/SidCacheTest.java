import jcifs.smb.*;

public class SidCacheTest {

    public static void main( String[] argv ) throws Exception {
        long t1, t2, t3;
        SmbFile file;
        ACE[] security;
        int ai;

        file = new SmbFile(argv[0]);
        t1 = System.currentTimeMillis();
        security = file.getSecurity(true);
        t2 = System.currentTimeMillis();
        security = file.getSecurity(true);
        t3 = System.currentTimeMillis();

        System.out.println("dt1=" + (t2 - t1) + ",dt2=" + (t3 - t2) + " " + ((t2 - t1) / (t3 - t2)) + "x increase");
    }
}
