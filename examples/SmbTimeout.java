import jcifs.smb.SmbFile;

public class SmbTimeout {

    public static void jcifsScan(String root, int sleepTime) throws Exception {
        long start = System.currentTimeMillis();
        SmbFile smbRoot = new SmbFile(root);
        SmbFile[] files = smbRoot.listFiles();
        for(SmbFile f : files) {
            System.out.println( f + ": " + f.canRead()+" : "+ f.length() + ": " + (System.currentTimeMillis()-start));
        Thread.sleep(sleepTime);
        }
    }

    public static void main(String[] p_args) throws Exception {
        if(p_args.length!=2) {
            System.out.println("Usage: <smbroot> <sleeptime(ms)>");
            return;
        }
        String smbRoot = p_args[0];
        int sleepTime = Integer.parseInt(p_args[1]);
        jcifsScan(smbRoot,sleepTime);
    }
        
}
