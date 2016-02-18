import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class NtlmHttpAuthExample extends HttpServlet {

    public void doGet( HttpServletRequest req,
                HttpServletResponse resp ) throws IOException, ServletException {
        PrintWriter out = resp.getWriter();

        resp.setContentType( "text/html" );
        out.println( "<HTML><HEAD><TITLE>NTLM HTTP Authentication Example</TITLE></HEAD><BODY>" );
        out.println( "<h2>NTLM HTTP Authentication Example</h2>" );

        out.println( req.getRemoteUser() + " successfully logged in" );

        out.println( "<h3>Please submit some form data using POST</h3>" );
        out.println( "<form action=\"NtlmHttpAuthExample\" method=\"post\">" );
        out.println( "<input type=\"text\" name=\"field1\" size=\"20\"/>" );
        out.println( "<input type=\"submit\"/>" );
        out.println( "</form>" );

        out.println( "field1 = " + req.getParameter( "field1" ));

        out.println( "</BODY></HTML>" );
    }
    public void doPost( HttpServletRequest req,
                HttpServletResponse resp ) throws IOException, ServletException {
        doGet( req, resp );
    }
}

