import java.io.*;

import java.net.*;

import jcifs.*;

public class NtlmHttpClient {

    public static void main(String[] args) throws Exception {
        // Normally set this outside application.
        // Note that as a side effect due to the way handlers are located,
        // you can also achieve this by simply doing:
             Config.registerSmbURLHandler();
        // which we already do to register the smb handler.
        //String pkgs = System.getProperty("java.protocol.handler.pkgs");
        //pkgs = (pkgs != null) ? "jcifs|" + pkgs : "jcifs";
        //System.setProperty("java.protocol.handler.pkgs", pkgs);
        //

        if (args == null || args.length < 4) {
            System.out.println("NtlmHttpClient <url> <domain> <user> <password>");
            System.exit(1);
        }
        String location = args[0];
        String domain = args[1];
        String user = args[2];
        String password = args[3];
        // can also specify these in the URL, i.e.
        //     http://DOMAIN%5cuser:password@host/dir/file.html
        // which will override these properties
        Config.setProperty("jcifs.smb.client.domain", domain);
        Config.setProperty("jcifs.smb.client.username", user);
        Config.setProperty("jcifs.smb.client.password", password);

        try {
            Config.setProperty("jcifs.netbios.hostname",
                    Config.getProperty("jcifs.netbios.hostname",
                            InetAddress.getLocalHost().getHostName()));
        } catch (Exception ex) { }
        URL url = new URL(location);
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(url.openStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
    }

}
