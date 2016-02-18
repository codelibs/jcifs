import java.util.*;
import javax.naming.*;
import javax.naming.directory.*;

public class DnsSrv {

    String getDomain(String name) throws NamingException {
        DirContext context;
        NameNotFoundException ret = null;

        context = new InitialDirContext();
        for ( ;; ) {
            try {
                Attributes attributes = context.getAttributes(
                    "dns:/_ldap._tcp.dc._msdcs." + name,
                    new String[] { "SRV" }
                );
                return name;
            } catch (NameNotFoundException nnfe) {
                ret = nnfe;
            }
            int dot = name.indexOf('.');
            if (dot == -1)
                break;
            name = name.substring(dot + 1);
        }

        throw ret != null ? ret : new NamingException("invalid name");
    }

    public static void main(String argv[]) throws Exception {
        DnsSrv dnsSrv = new DnsSrv();
        System.out.println(dnsSrv.getDomain(argv[0]));
    }
}

