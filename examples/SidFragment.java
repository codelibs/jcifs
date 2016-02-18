import jcifs.smb.*;

public class SidFragment {

    public static void main(String[] argv) throws Exception {
        if (argv.length < 1) {
            System.err.println("usage: SidFragment <textual domain sid>");
            return;
        }

        SID domsid = new SID(argv[0]);
        int rid = 1120;
        int count = 150;
        int si;

        SID[] sids = new SID[count];

        for (si = 0; si < sids.length; si++) {
            sids[si] = new SID(domsid, rid++);
        }

        SID.resolveSids("ts0", null, sids);

        for (si = 0; si < sids.length; si++) {
            System.out.println(sids[si].toString());
        }
    }
}
