/**
 * Copyright 2008-2012. Joe Khoobyar. All Rights Reserved.
 */
package name.khoobyar.joe.jsch.sspi;

import static com.sun.jna.platform.win32.Sspi.ISC_REQ_DELEGATE;
import static com.sun.jna.platform.win32.Sspi.ISC_REQ_INTEGRITY;
import static com.sun.jna.platform.win32.Sspi.ISC_REQ_MUTUAL_AUTH;
import static com.sun.jna.platform.win32.Sspi.SECPKG_CRED_OUTBOUND;
import name.khoobyar.joe.gsspi.win32.Sspi;
import name.khoobyar.joe.gsspi.win32.SspiUtils;

import com.jcraft.jsch.JSchException;
import com.sun.jna.platform.win32.Sspi.CredHandle;
import com.sun.jna.platform.win32.Sspi.CtxtHandle;
import com.sun.jna.platform.win32.Sspi.TimeStamp;
import com.sun.jna.ptr.NativeLongByReference;

public class GSSContextSSPI
	implements com.jcraft.jsch.GSSContext
{
	//private SecPkgContext_Sizes sspiSizes;
	private transient SSPIState sspiState;
	private transient CtxtHandle contextHandle;
	private transient CredHandle credHandle;
	private transient TimeStamp credStamp;
	
	private String credName;
	private String credKrbName;
	private String serverName;
	private String serverKrbName;
	
	public GSSContextSSPI () {
		SspiUtils.requireSecurityPackage ("Kerberos");
	}

	public void create (String user, String host) throws JSchException {
		// Reset our internal state before doing anything...
		dispose ();
		
		// Identify the service principal for the given host.
		serverName = SspiUtils.getQualifiedHostName (host);
		serverKrbName = SspiUtils.getServicePrincipalName ("host", serverName);
		
		// Acquire credentials for the given user.
		TimeStamp credStamp = new TimeStamp ();
		CredHandle credHandle = SspiUtils.getUserCredentials (user, "Kerberos", SECPKG_CRED_OUTBOUND, credStamp);
		
		// Identify the user principal.
	    try {
	    	credKrbName = SspiUtils.getUserPrincipalName (credHandle);
	    	int i = Math.max (credKrbName.lastIndexOf ('/'), credKrbName.lastIndexOf ('@'));
    		credName = i < 0 ? user : credKrbName.substring (0, i);
	    } catch (RuntimeException e) {
	    	SspiUtils.dispose (credHandle);
	    	throw e;
	    }
	    
	    // Save the handles.
	    this.credHandle = credHandle;
	    this.credStamp = credStamp;
	}

	/** @return <tt>true</tt> if the the GSS context is established. */
	public boolean isEstablished() {
		return contextHandle!=null && ! contextHandle.isNull () && (sspiState==null || sspiState.isValid ());
	}

	public byte[] init (byte[] token, int s, int l) throws JSchException {
	    if (credHandle==null || credHandle.isNull ())
            throw new IllegalStateException ("A credentials handle must be acquired first");

		// Prepare arguments and process any previous state.
		TimeStamp ctxStamp = new TimeStamp ();
		NativeLongByReference outAttrs = new NativeLongByReference ();
		CtxtHandle ctxHandle = (sspiState != null && sspiState.handle != null) ? sspiState.handle : new CtxtHandle ();
		token = asArray(token, s, l);
	
		// Get a security context and token.
		try {
			token = SspiUtils.initSecurityContext (credHandle, ctxHandle, serverKrbName, ISC_REQ_DELEGATE |
			                                       ISC_REQ_MUTUAL_AUTH | ISC_REQ_INTEGRITY/* | ISC_REQ_ALLOCATE_MEMORY */,
			                                       true, token, outAttrs, ctxStamp);
			sspiState = new SSPIState (outAttrs.getValue ().intValue (), ctxHandle, ctxStamp, token);
		}
		
		// Clean up any dangling handles after encountering errors.
		catch (Exception e) {
			SspiUtils.dispose (ctxHandle);
			dispose ();
			if (e instanceof JSchException)
				throw (JSchException) e;
			throw (RuntimeException) e;
		}
		
		// Finish up the token if it is done.
		if (sspiState.isValid ())
			this.contextHandle = sspiState.handle;
		return sspiState.data;
	}

	public byte[] getMIC(byte[] message, int s, int l) {
		if (!isEstablished ())
            throw new IllegalStateException ("The security context must be established first.");
		return SspiUtils.makeSignature (contextHandle, asArray (message, s, l), 0);
	}

	/** Disposes of any handles and resets transient internal state. */
	public void dispose () {
		SspiUtils.dispose (contextHandle);
		SspiUtils.dispose (credHandle);
		sspiState = null;
		contextHandle = null;
		credHandle = null;
		credStamp = null;
	}

	/** Returns a range from the given array, avoiding array copying whenever possible. */
	private byte[] asArray (byte[] token, int s, int l) {
		if (token==null || (s==0 && l==token.length))
			return token;
		byte data[] = new byte[l];
		System.arraycopy (token, s, data, 0, l);
		return data;
	}

	/**Holds curent SSPI state.
	 *
	 * @author Joe Khoobyar
	 */
	public class SSPIState {
	    int attrs;
	    CtxtHandle handle;
	    TimeStamp stamp;
	    byte data[];
		
	    public SSPIState (int attrs, CtxtHandle handle, TimeStamp stamp, byte data[]) {
	    	this.attrs = attrs;
	    	this.handle = handle;
	    	this.stamp = stamp;
	    	this.data = data;
		}
	    
	    public boolean isValid () {
			return 0 == (attrs & Sspi.ISC_RET_INTERMEDIATE_RETURN);
	    }
	}
}
