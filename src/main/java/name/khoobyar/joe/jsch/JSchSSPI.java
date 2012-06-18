/**
 * Copyright 2008-2012 Joe Khoobyar.
 */
package name.khoobyar.joe.jsch.sspi;

import com.jcraft.jsch.JSch;

/**Simplifies usage of JSch with SSPI support on Windows XP or above.
 *
 *
 * @author Joe Khoobyar
 */
public abstract class JSchSSPI {

	/** Conditionally configure the given JSch instance
	 *  for SSPI support if the host OS is Windows XP or above.
	 *
	 *  Otherwise, the configuration of the given JSch instance will be left as is.
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

