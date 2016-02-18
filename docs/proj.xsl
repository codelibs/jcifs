<?xml version="1.0"?>

<!--
proj.xsl - XSLT style-sheet for generating a project web page
Copyright (C) 2002 Michael B. Allen

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
-->

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


<xsl:template match="proj">
	<HTML><HEAD>
	<STYLE TYPE="text/css">
		BODY {
			background-color: <xsl:value-of select="$edge"/>;
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
		}
		TH, TD {
			font-family: verdana, arial;
			font-size: small;
		}
		.mainpane {
			background-color: <xsl:value-of select="$mainpane"/>;
			padding: 10px;
		}
		.leftpane {
			background-color: <xsl:value-of select="$leftpane"/>;
			padding: 10px;
		}
		.middlepane {
			background-color: <xsl:value-of select="$middlepane"/>;
			padding: 10px;
		}
		.footer {
			background-color: <xsl:value-of select="$footer"/>;
		}
	</STYLE>
	<TITLE><xsl:value-of select="title"/></TITLE>
	</HEAD><BODY>
	<TABLE>
	<TR><TD colspan="2" class="mainpane">
<!--
		<BIG><xsl:value-of select="title"/></BIG><BR/>
-->
<center>
		<img src="jcifs.png" alt="JCIFS"/>
		<H2><xsl:value-of select="short"/></H2>
</center>
		<P/>
		<xsl:apply-templates select="desc"/>
	</TD></TR><TR><TD valign="top" width="350" class="leftpane">
		<xsl:apply-templates select="links"/>
	</TD><TD valign="top" class="middlepane">
		<xsl:apply-templates select="news"/>
	</TD></TR><TR><TD colspan="2" class="footer">
		<hr noshade="noshade"/>
		<small>
		Last updated <xsl:value-of select="$date"/><BR/>
		<xsl:value-of select="$lib"/><BR/>
		Copyright &#169; 2014 <xsl:value-of select="$copyright"/><BR/>
		<a href="http://validator.w3.org/check/referer" style="color: black;">validate this page</a>
		</small>
	</TD></TR></TABLE>
	</BODY></HTML>
</xsl:template>

<xsl:template match="links">
	<h1>Links</h1>
	<xsl:for-each select="a">
		<xsl:apply-templates select="."/><br/>
	</xsl:for-each>
	<xsl:for-each select="group">
		<h2><xsl:value-of select="title"/></h2>
		<xsl:if test="desc">
			<small><xsl:apply-templates select="desc"/></small><br/>
		</xsl:if>
		<xsl:for-each select="a">
			<xsl:apply-templates select="."/><br/>
		</xsl:for-each>
	</xsl:for-each>
</xsl:template>

<xsl:template match="news">
	<h1>News</h1>
	<xsl:for-each select="entry[not(@old)]">
		<xsl:if test="@adsense">
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
		</xsl:if>
		<EM><xsl:value-of select="title"/></EM><BR/>
		<SMALL><B><xsl:value-of select="sub"/></B></SMALL><BR/>
		<xsl:apply-templates select="desc"/>
		<P/>
	</xsl:for-each>
</xsl:template>

<xsl:template match="desc/ident">
	<I><xsl:apply-templates/></I>
</xsl:template>

<xsl:template match="desc">
	<xsl:apply-templates/>
</xsl:template>

</xsl:stylesheet>
