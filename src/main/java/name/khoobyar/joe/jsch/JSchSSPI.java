/**
 * Copyright 2008-2012 Joe Khoobyar.
 */
package name.khoobyar.joe.jsch;

import com.jcraft.jsch.JSch;

/**	<h3>Simplifies usage of JSch with native Kerberos support on Windows XP or above.
 *	</h3>
 *
 *	<h6>
 *	Target audience
 *	</h6>
 *
 *  <p>Developers who want/need transparent support for single sign-on from Windows clients
 *  to SSH servers (Windows or Linux).  Assumes that your Kerberos provider on Windows integrates
 *	with Microsoft's SSPI (as a security provider implementation) - since this is why you would be interested in the first place.
 *
 *	<h6>
 *	Background Information <small>(why this library is useful at all)</small>
 *	</h6>
 *	<p>
 *  Microsoft Windows provides it's own <em>Kerberos vendor-neutral</em> API called SSPI
 *	that is semantically <em>very</em> similar to the GSS API supported by most other major 
 *	operating systems.  Recent Java releases from Oracle, however, <em>still</em> do not provide
 *	support for integrating with this non-standard GSS alternative this Microsoft, even after working patches have been provided by the community over at Open JDK for about four years now.
 *	</p>
 *	<p>
 *	Vendors providing single sign-on on Windows intranets generally don't provide support for all things Java Security.  However, this support can be quite effective at increasing IT staff productivity within a corporate LAN environment - especially if those intranets support cross-forest authentication a mixed (Windows/Linux) environment).
 *	</p>
 *
 * @author Joe Khoobyar
 */
public class JSchSSPI
	extends JSch
{

	/** 
	 *	Simplest way to <em>create</em> a JSch instance that supports native Kerberos
	 *	implementations on Windows XP or above.
	 */
	public JSchSSPI () {
		super ();
		configure (this);
	}

	/** Simplest way to <em>configure</em> an existing JSch that supports native Kerberos
	 *	implementations on Windows XP or above.
	 */
	public static JSch configure (JSch jsch) {
		String osname = System.getProperty ("os.name");
		if (osname!=null && osname.toLowerCase().startsWith ("windows")) {
			String osver = System.getProperty ("os.version");
			if (osver != null) {
				osver = osver.trim ();
				int n = osver.indexOf ('.');
				if (n > 0)
					osver = osver.substring (0, n);
				if (Integer.parseInt (osver) >= 5)
					configureForSSPI (jsch);
			}
		}
		return jsch;
	}

	/** Configures the given JSch instance for SSPI support.
	 *  Assumes that the host OS is at least Windows XP.
	 */
	protected static void configureForSSPI (JSch jsch) {
		jsch.setConfig ("gssapi-with-mic.krb5", "name.khoobyar.joe.jsch.sspi.GSSContextSSPI");
	}
}

