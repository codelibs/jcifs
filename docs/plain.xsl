<?xml version="1.0"?>

<xsl:stylesheet version="1.0"
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="html"
	encoding="ISO-8859-1"
	doctype-public="-//W3C//DTD HTML 4.01 Transitional//EN"/>

<xsl:param name="date" select="''"/>
<xsl:param name="lib" select="''"/>
<xsl:param name="title" select="''"/>
<xsl:param name="copyright" select="''"/>
<xsl:param name="edge" select="''"/>
<xsl:param name="mainpane" select="''"/>
<xsl:param name="leftpane" select="''"/>
<xsl:param name="middlepane" select="''"/>
<xsl:param name="footer" select="''"/>
<xsl:param name="text1" select="''"/>
<xsl:param name="text2" select="''"/>

<!-- The Identity Transformation -->
<xsl:template match="/|@*|node()">
   <xsl:copy>
     <xsl:apply-templates select="@*|node()"/>
   </xsl:copy>
</xsl:template>

<xsl:template match="topic">
	<HTML><HEAD>
	<STYLE TYPE="text/css">
		BODY {
			font-family: verdana, arial;
			font-size: small;
			background-color: #ffffff;
		}
		H1 {
			font-family: verdana, arial;
			font-size: normal;
			color: <xsl:value-of select="$text1"/>;
		}
		H2 {
			font-family: arial, verdana;
			font-size: normal;
			color: <xsl:value-of select="$text1"/>;
		}
		H3 {
			font-family: arial, verdana;
			font-size: small;
			color: <xsl:value-of select="$text2"/>;
		}
		A {
			font-family: arial, verdana;
			font-weight: bold;
			color: <xsl:value-of select="$text2"/>;
		}
		A:HOVER {
			text-decoration: none;
		}
		BIG {
			color: <xsl:value-of select="$text2"/>;
			font-family: arial, verdana;
			font-weight: bold;
			font-size: 50px;
		}
		EM {
			color: <xsl:value-of select="$text2"/>;
			font-family: Times New Roman;
			font-weight: bold;
			font-size: 20px;
		}
		PRE {
		    font-family: monospaced, courier;
		    border: 1px lightgrey dotted;
		    white-space: pre; 
		    color: black;
			padding: 4px;
			background-color: #f0f0f0; 
		}
		TABLE {
			border-collapse: collapse;
			border: 1px lightgrey solid;
		}
		TH {
			font-family: verdana, arial;
			border: 1px lightgrey solid;
			background-color: #f0f0f0;
		}
		TD {
			font-family: verdana, arial;
			font-size: small;
			border: 1px lightgrey solid;
		}
	</STYLE>
	<TITLE></TITLE>
	</HEAD><BODY>
	<xsl:if test="@adsense">
<center>
<script type="text/javascript">&lt;!--
google_ad_client = "pub-9339567651298204";
google_ad_width = 728;
google_ad_height = 90;
google_ad_format = "728x90_as";
google_ad_type = "text";
google_ad_channel ="";
google_color_border = "E0E0FF";
google_color_bg = "FFFFFF";
google_color_link = "000080";
google_color_url = "808080";
google_color_text = "000000";
//--&gt;</script>
<script type="text/javascript"
  src="http://pagead2.googlesyndication.com/pagead/show_ads.js">
  </script>
<P/>
</center>
	</xsl:if>

	<xsl:apply-templates/>

	<HR noshade="noshade"/>
	<SMALL>
	Last updated <xsl:value-of select="$date"/><BR/>
	<xsl:value-of select="$lib"/><BR/>
	Copyright &#169; 2004 <xsl:value-of select="$copyright"/><BR/>
	<a href="http://validator.w3.org/check/referer" style="color: black;">validate this page</a>
	</SMALL>

	</BODY></HTML>
</xsl:template>

<xsl:template match="title">
	<H1><xsl:apply-templates/></H1>
</xsl:template>

</xsl:stylesheet>

