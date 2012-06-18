/**
 * Copyright 2008-2012. Joe Khoobyar. All Rights Reserved.
 */
package name.khoobyar.joe.jsch.sspi;

import static com.sun.jna.platform.win32.Secur32.*;
import static com.sun.jna.platform.win32.Sspi.ISC_REQ_ALLOCATE_MEMORY;
import static com.sun.jna.platform.win32.Sspi.ISC_REQ_DELEGATE;
import static com.sun.jna.platform.win32.Sspi.ISC_REQ_INTEGRITY;
import static com.sun.jna.platform.win32.Sspi.ISC_REQ_MUTUAL_AUTH;
import static com.sun.jna.platform.win32.Sspi.MAX_TOKEN_SIZE;
import static com.sun.jna.platform.win32.Sspi.SECBUFFER_DATA;
import static com.sun.jna.platform.win32.Sspi.SECBUFFER_TOKEN;
import static com.sun.jna.platform.win32.Sspi.SECPKG_CRED_OUTBOUND;
import static com.sun.jna.platform.win32.Sspi.SECURITY_NATIVE_DREP;
import static com.sun.jna.platform.win32.W32Errors.SEC_E_SECPKG_NOT_FOUND;
import static com.sun.jna.platform.win32.W32Errors.SEC_I_COMPLETE_NEEDED;
import static com.sun.jna.platform.win32.W32Errors.SEC_I_COMPLETE_AND_CONTINUE;

import java.net.InetAddress;
import java.net.UnknownHostException;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Logger;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.Secur32;
import com.sun.jna.platform.win32.Secur32Util;
import com.sun.jna.platform.win32.Sspi;
import com.sun.jna.platform.win32.Sspi.SecBuffer;
import com.sun.jna.platform.win32.Secur32Util.SecurityPackage;
import com.sun.jna.platform.win32.Sspi.CredHandle;
import com.sun.jna.platform.win32.Sspi.CtxtHandle;
import com.sun.jna.platform.win32.Sspi.TimeStamp;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.NativeLongByReference;
import com.sun.jna.ptr.PointerByReference;
import name.khoobyar.joe.jsch.sspi.Utils.Secur32.SecBufferDesc;

public class GSSContextSSPI
	implements com.jcraft.jsch.GSSContext
{
	//private SecPkgContext_Sizes sspiSizes;
	private SSPIState sspiState;

	private CtxtHandle contextHandle;
	//private TimeStamp contextStamp;

	private CredHandle credHandle;
	private TimeStamp credStamp;
	private String credName;
	private String credKrbName;

	private String serverName;
	private String serverKrbName;
	
	static {
		Native.setProtected (true);
	}

	public GSSContextSSPI () {
		for (SecurityPackage pkg : Secur32Util.getSecurityPackages())
			if (pkg.name.equalsIgnoreCase ("Kerberos"))
				return;
	    Utils.assertUnchecked (SEC_E_SECPKG_NOT_FOUND, "GSSContextSSPI<init>");
	}

	public void create (String user, String host) throws JSchException {
		CredHandle credHandle = new CredHandle ();
		TimeStamp credStamp = new TimeStamp ();
		//SecPkgContext_Names names = null;

		// Canonicalize the host name.
		try { serverName = InetAddress.getByName (host).getCanonicalHostName (); }
		catch (UnknownHostException e) { throw new JSchException ("Failed to canonicalize host name: " + host, e); }
		serverKrbName = "host/" + serverName;

		// Destroy any old handle that's hanging around.
		if (this.credHandle!=null && ! this.credHandle.isNull ())
			Secur32.INSTANCE.FreeCredentialsHandle (this.credHandle);
		this.credHandle = null;
    	this.credStamp = null;
    	this.credName = this.credKrbName = null;

		// Get the credentials handle.
	    Utils.assertOk (
	    	Secur32.INSTANCE.AcquireCredentialsHandle (
				null, "Kerberos", new NativeLong (SECPKG_CRED_OUTBOUND),
				null, null, null, null, credHandle, credStamp
			),
			"AcquireCredentialsHandle"
		);
	    try {
	    	
		    // Get principal name for the credentials.
	    	char credNameBuffer[] = new char[255];
	    	IntByReference credNameLength = new IntByReference (credNameBuffer.length);
	    	if (Secur32.INSTANCE.GetUserNameEx (EXTENDED_NAME_FORMAT.NameUserPrincipal, credNameBuffer, credNameLength)) {
	    		credName = new String (credNameBuffer, 0, credNameLength.getValue ());
				int i = credName.indexOf ('\\');
		        if (i >= 0)
		        	credName = credName.substring (i + 1);
		        credKrbName = credName.replace ('@', '/');
	    	} else {
			    Utils.assertOk (Kernel32.INSTANCE.GetLastError (), "GetUserNameEx");
	    	}
	    	
	    	/*
			names = new SecPkgContext_Names ();
		    Utils.assertOk (
				API.QueryCredentialsAttributes (credHandle, new NativeLong (SECPKG_ATTR_NAMES), names),
				"QueryCredentialsAttributes"
			);
		    try {
				credName = names.getUserName ();
				int i = credName.indexOf ('\\');
		        if (i >= 0)
		        	credName = credName.substring (i + 1);
		        credKrbName = credName.replace ('@', '/');
		    }
		    finally {
				API.FreeContextBuffer (names.sUserName);
		    }
		    
		    // Mark it as successful.
		    names = null;
		    */
	    }
	    finally {
	    	// Clean up on error...
	    	if (credName == null) {
				Secur32.INSTANCE.FreeCredentialsHandle (credHandle);
	    		credHandle = null;
	    		credStamp = null;
	    	}
	    }
	    
	    // Save the handles.
	    if (credHandle==null || credHandle.isNull ())
            throw new JSchException ("Failed to acquire a credentials handle");
	    this.credHandle = credHandle;
	    this.credStamp = credStamp;
	}

	/** @return <tt>true</tt> if the the GSS context is established. */
	public boolean isEstablished() {
		return contextHandle!=null && ! contextHandle.isNull () && (sspiState==null || sspiState.lastResult==0);
	}

	public byte[] init (byte[] token, int s, int l) throws JSchException {
		
		// Sanity check.
	    if (credHandle==null || credHandle.isNull ())
            throw new IllegalStateException ("A credentials handle must be acquired first");

		// Prepare arguments and process any previous state.
	    int result = 0;
		TimeStamp ctxStamp = new TimeStamp ();
		CtxtHandle ctxHandle = new CtxtHandle (), prevHandle = null;
		NativeLongByReference outputFlags = new NativeLongByReference (new NativeLong (0));
		SecBufferDesc input = null, buffers = new SecBufferDesc (SECBUFFER_TOKEN, MAX_TOKEN_SIZE);
		if (sspiState != null && sspiState.handle != null)
			prevHandle = sspiState.handle;
		if (token!=null && s>=0 && l>0) {
			byte data[] = new byte[l];
			System.arraycopy (token, s, data, 0, l);
			input = new SecBufferDesc (SECBUFFER_TOKEN, data);
		}
	
		// Get a security context and token.
		try {
			result = Utils.Secur32.INSTANCE.InitializeSecurityContext (
				credHandle, prevHandle, serverKrbName,
				// ISC_REQ_ALLOCATE_MEMORY | 
				new NativeLong (ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH | ISC_REQ_INTEGRITY),
				new NativeLong (0), new NativeLong (SECURITY_NATIVE_DREP),
				input, new NativeLong (0), ctxHandle, buffers, outputFlags, ctxStamp
			);
	    	String message = Utils.logAndDecode ("InitializeSecurityContext", result);
			if (result < 0)
				throw new JSchException (message);
		    if (SEC_I_COMPLETE_NEEDED == result || SEC_I_COMPLETE_AND_CONTINUE == result)
		    	Utils.assertOk (Utils.Secur32.INSTANCE.CompleteAuthToken (ctxHandle, buffers), "CompleteAuthToken");
			sspiState = new SSPIState (result, ctxHandle, ctxStamp, buffers.getBytes ());
		}
		
		// Clean up any dangling handles after encountering errors.
		catch (Exception e) {
			if (prevHandle == null)
				prevHandle = ctxHandle;

			if (prevHandle!=null && ! prevHandle.isNull ())
				try { Secur32.INSTANCE.DeleteSecurityContext (prevHandle); }
				finally { sspiState = null; }
				
			try { Secur32.INSTANCE.FreeCredentialsHandle (this.credHandle); }
			finally { this.credHandle = null; this.credStamp = null; this.credName = null; }

			if (e instanceof JSchException)
				throw (JSchException) e;
			throw (RuntimeException) e;
		}
		
		// Free any buffers that were allocated by the SSPI provider.
		finally {
			/*
			SecBuffer buffer = buffers.at (0);
			if (buffer.buffer != null)
				Utils.assertOk (API.FreeContextBuffer (buffer.buffer), "FreeContextBuffer");
			*/
		}
		
		// Finish up the token if it is done.
		if (sspiState.lastResult == 0) {
			
			// Destroy any old handle that's hanging around.
			if (this.contextHandle!=null && ! this.contextHandle.isNull ())
				try { Secur32.INSTANCE.DeleteSecurityContext (this.contextHandle); }
				finally { this.contextHandle = null; }
			/*
			// Get information about sizes and lengths related to this transport.
			sspiSizes = new SecPkgContext_Sizes ();
			Utils.assertOk (
				API.QueryContextAttributes (sspiState.handle, new NativeLong (SECPKG_ATTR_SIZES), sspiSizes),
				"QueryContextAttributes(SECPKG_ATTR_SIZES)"
			);

			// Get the names of entities related to this connection.
			SecPkgContext_Names names = new SecPkgContext_Names ();
			try {
				Utils.assertOk (
					API.QueryContextAttributes (sspiState.handle, new NativeLong (SECPKG_ATTR_NAMES), names),
					"QueryContextAttributes(SECPKG_ATTR_NAMES)"
				);
			}
			finally {
				Utils.assertOk (API.FreeContextBuffer (names.sUserName), "FreeContextBuffer");
			}
			SecPkgContext_NativeNames nnames = new SecPkgContext_NativeNames ();
			try {
				Utils.assertOk (
					API.QueryContextAttributes (sspiState.handle, new NativeLong (SECPKG_ATTR_NATIVE_NAMES), nnames),
					"QueryContextAttributes(SECPKG_ATTR_NATIVE_NAMES)"
				);
			}
			finally {
				Utils.assertOk (API.FreeContextBuffer (nnames.sClientName), "FreeContextBuffer");
				Utils.assertOk (API.FreeContextBuffer (nnames.sServerName), "FreeContextBuffer");
			}
			*/
			
			this.contextHandle = sspiState.handle;
		}
		
		else if (sspiState.lastResult < 0) {
			Utils.logAndDecode (Logger.ERROR, "SSPI - Last result", sspiState.lastResult);
            throw new JSchException ("SSPI error " + sspiState.lastResult);
		}

		return sspiState.data;
	}

	public byte[] getMIC(byte[] message, int s, int l) {
		byte input[] = new byte[l];
		System.arraycopy (message, s, input, 0, l);
		
		SecBuffer.ByReference buffer = new SecBuffer.ByReference (SECBUFFER_DATA, input);
		SecBufferDesc buffers = new SecBufferDesc ((SecBuffer.ByReference[]) buffer.toArray(2));
		
		buffer = buffers.getBuffer (1);
		buffer.BufferType = new NativeLong (SECBUFFER_TOKEN);
		buffer.cbBuffer = new NativeLong (MAX_TOKEN_SIZE);
		buffer.pvBuffer = new Memory (MAX_TOKEN_SIZE);
		
		Utils.assertUnchecked (sspiState.lastResult =
			Utils.Secur32.INSTANCE.MakeSignature (contextHandle, new NativeLong (0), buffers, new NativeLong (0)),
			"MakeSignature"
		);
	
		buffer.read ();
		return buffer.getBytes ();

		//SecBuffer.ByReference data = new SecBuffer.ByReference (SECBUFFER_DATA, input);
		//data.toArray (2);

		/*
		SecBufferDesc buffers = new SecBufferDesc ;
		buffers.
		buffers.at (1).fill (SECBUFFER_TOKEN, sspiSizes.cbMaxSignature.intValue ());

		Utils.assertUnchecked (sspiState.lastResult =
			API.MakeSignature (contextHandle, new NativeLong (0), buffers, new NativeLong (0)),
			"MakeSignature"
		);
		
		return buffers.at (1).toByteArray ();
		*/
	}

	public void dispose () {
		try {
			if (contextHandle!=null && ! contextHandle.isNull ())
				Secur32.INSTANCE.DeleteSecurityContext (contextHandle);
			if (credHandle!=null && ! credHandle.isNull ())
				Secur32.INSTANCE.FreeCredentialsHandle (credHandle);
		} finally { 
			sspiState = null;
			contextHandle = null;
			credHandle = null;
		}
	}

	/**Holds curent SSPI state.
	 *
	 * @author Joe Khoobyar
	 */
	public class SSPIState {
	    int lastResult;
	    CtxtHandle handle;
	    TimeStamp stamp;
	    byte data[];
		
	    public SSPIState (int result, CtxtHandle handle, TimeStamp stamp, byte data[]) {
	    	this.lastResult = result;
	    	this.handle = handle;
	    	this.stamp = stamp;
	    	if (data != null) {
		    	this.data = new byte [data.length];
		    	System.arraycopy (data, 0, this.data, 0, data.length);
	    	} else {
	    		this.data = null;
	    	}
		}
	}
}
