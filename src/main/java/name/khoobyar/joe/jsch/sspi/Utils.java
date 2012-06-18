/**
 * Copyright 2008-2012 Joe Khoobyar.
 */
package name.khoobyar.joe.jsch.sspi;

import static com.sun.jna.platform.win32.W32Errors.SEC_E_OK;
import static com.sun.jna.platform.win32.Sspi.SECBUFFER_EMPTY;
import static com.sun.jna.platform.win32.Sspi.SECBUFFER_TOKEN;
import static com.sun.jna.platform.win32.Sspi.SECBUFFER_VERSION;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Logger;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.Sspi.CtxtHandle;
import com.sun.jna.platform.win32.Sspi.CredHandle;
import com.sun.jna.platform.win32.Sspi.SecBuffer;
import com.sun.jna.platform.win32.Sspi.TimeStamp;
import com.sun.jna.ptr.NativeLongByReference;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIOptions;

/**SSPI calls and structures.
 *
 * @author Joe Khoobyar
 */
public class Utils {
	private static Logger jschLogger;

	static {
		jschLogger = null;
	}
	
	public static void setLogger (Logger logger) {
		jschLogger = logger;
	}

	public static void log (int level, String message) {
		if (jschLogger != null)
			jschLogger.log (level, "SSPI: " + message);
	}

	public static void log (String message) {
		log (Logger.INFO, message);
	}

	/** Helper function for building a message and decoding an SSPI result code
	 *  from a Win32 API function.
	 */
	public static String decodeResult (String message, int result) {
		if (result == SEC_E_OK)
			return message;

		StringBuilder sb = new StringBuilder ();
		if (message!=null)
			sb.append (message).append (" (");

		if (result < 0)
			sb.append ("ERROR");
		else
			sb.append ("result");
		sb.append (" 0x").append (Integer.toHexString (result));
		
		if (message!=null)
			sb.append (")");

		return sb.toString ();
	}
	
	public static String logAndDecode (int level, String message, int result) {
		if (result != SEC_E_OK)
			message = decodeResult (message, result);
    	log (level, message);
    	return message;
	}
	
	public static String logAndDecode (String message, int result) {
		return logAndDecode (result<0 ? Logger.ERROR : Logger.INFO, message, result);
	}
	
	public static void assertUnchecked (int result, String message) throws RuntimeException {
		message = logAndDecode (message, result);
	    if (result != SEC_E_OK)
			throw new RuntimeException (message);
	}
	
	public static void assertOk (int result, String message) throws JSchException {
		message = logAndDecode (message, result);
	    if (result != SEC_E_OK)
			throw new JSchException (message);
	}
	
	public interface Secur32 extends StdCallLibrary {
		Secur32 INSTANCE = (Secur32) Native.loadLibrary ("Secur32", Secur32.class, W32APIOptions.UNICODE_OPTIONS);
		
		public static class SecBufferDesc extends Structure {
			
			/** Version number. */
		    public NativeLong ulVersion;
		    
		    /** Number of buffers. */
		    public NativeLong cBuffers;
		    
		    /** Array of buffers. */
		    public SecBuffer.ByReference pBuffer;
		    
		    /** Last used Java array. */
		    private transient Object buffers[];
		    
		    /** Create a new SecBufferDesc. */
		    public SecBufferDesc (SecBuffer.ByReference buffers[]) {
		    	this.ulVersion = new NativeLong(SECBUFFER_VERSION);
		    	this.cBuffers = new NativeLong(buffers.length);
		    	this.pBuffer = buffers[0];
		    	this.buffers = buffers;
		    	allocateMemory ();
		    }
		    
		    /** Create a new SecBufferDesc with one buffer. */
		    public SecBufferDesc (SecBuffer.ByReference buffer) {
		    	this ((SecBuffer.ByReference[]) buffer.toArray (1));
		    }
		    
		    /** Create a new SecBufferDesc with one SECBUFFER_EMPTY buffer. */
		    public SecBufferDesc () {
		    	this (new SecBuffer.ByReference ());
		    }
		    
		    /**
		     * Create a new SecBufferDesc with initial data.
		     * @param type    Token type.
		     * @param token   Initial token data.
		     */
		    public SecBufferDesc (int type, byte[] token) {
		    	this (new SecBuffer.ByReference(type, token));
		    }
		    
		    /**
		     * Create a new SecBufferDesc with one SecBuffer of a given type and size.
		     * @param type
		     * @param tokenSize
		     */
		    public SecBufferDesc (int type, int tokenSize) {
		    	this (new SecBuffer.ByReference (type, tokenSize));
		    }
		    
		    /**
		     * Create a new SecBufferDesc with the given number of buffers.
		     * @param type
		     * @param tokenSize
		     */
		    public SecBufferDesc (int buffers) {
		    	this ((SecBuffer.ByReference[]) new SecBuffer.ByReference().toArray (2));
		    }
		    
		    private void syncArray () {
	    		if (buffers!=null && buffers[0] == pBuffer)
					return;
				buffers = pBuffer.toArray (cBuffers.intValue ());
				pBuffer = (SecBuffer.ByReference) buffers[0];
		    }
		    
		    public SecBuffer.ByReference getBuffer (int buffer) {
		    	if (pBuffer == null || cBuffers == null)
		    		throw new RuntimeException("pBuffers | cBuffers");
		    	if (cBuffers.intValue () < buffer)
			    	throw new RuntimeException("cBuffers < "+buffer);
		    	syncArray ();
	    		return (SecBuffer.ByReference) buffers[buffer];
		    }
		    
		    public byte[] getBytes(int buffer) {
		    	SecBuffer.ByReference secBuffer = getBuffer (buffer);
		    	return secBuffer.cbBuffer.intValue()==0 ? null : secBuffer.getBytes ();
		    }
		    
		    public byte[] getBytes() {
				return getBytes (0);
			}
		}

		/** Win32 API function (see MSDN for details) */
		public int InitializeSecurityContext (CredHandle phCredential, CtxtHandle phContext,
				String pszTargetName, NativeLong fContextReq,
				NativeLong reserved1, NativeLong targetDataRep,
				SecBufferDesc pInput, NativeLong reserved2,
				CtxtHandle phNewContext, SecBufferDesc pOutput,
				NativeLongByReference pfContextAttr,
				TimeStamp ptsExpiry
			);

		/** Win32 API function (see MSDN for details) */
		public int CompleteAuthToken (CtxtHandle phContext, SecBufferDesc pToken);

		/** Win32 API function (see MSDN for details) */
		public int MakeSignature (CtxtHandle phContext, NativeLong fQOP,
				                  SecBufferDesc pToken, NativeLong messageSeqNo);

	}
}
