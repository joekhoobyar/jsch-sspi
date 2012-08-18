import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Logger;
import com.jcraft.jsch.Session;

import name.khoobyar.joe.jsch.JSchSSPI;

public class Transfer {

	public static void main(String[] arg) {
		try {
			if (arg.length < 2) {
				System.err.println ("usage: Transfer hostname file(s)");
				System.exit (-1);
			}

			String host = arg[0];
			String files[] = new String[arg.length-1];
			System.arraycopy (arg, 1, files, 0, arg.length-1);
			String user = System.getProperty ("user.name");
			String home = System.getProperty ("user.home");
			Logger logger = new Logger() {
				public boolean isEnabled(int level) { return true; }
				public void log(int level, String message) { System.out.println(message); }
			};
			
			JSch jsch = new JSchSSPI ();
			jsch.setKnownHosts (home+File.separator+".ssh"+File.separator+"known_hosts");
			JSch.setLogger (logger);
			for (int i = 0; i < 10; i++) {
				for (String path : files) {
					File file = new File (path);
					String name = file.getName ();

					Session session = jsch.getSession (user, host, 22);
					try {
		
						// session.setPassword("your password");
			
						// username and password will be given via UserInfo interface.
						//UserInfo ui = new MyUserInfo();
						//session.setUserInfo(ui);
						session.setConfig("PreferredAuthentications", "gssapi-with-mic");
						//session.setConfig("GSSAPIAuthentication", "yes");
						//session.setConfig("GSSAPIDelegateCredentials", "yes");
						// session.setConfig("gssapi-with-mic.krb5", "com.jcraft.jsch.sspi.GSSContextSSPI");
						session.setConfig("StrictHostKeyChecking", "no");
			
						// session.connect();
						session.connect(30000); // making a connection with timeout.
	
						ChannelExec channel = (ChannelExec) session.openChannel ("exec");
						channel.setCommand ("scp -p -t \""+name+"-"+i+"\"");
		
						FileInputStream source = new FileInputStream (file);
						InputStream in = channel.getInputStream ();
						OutputStream out = channel.getOutputStream ();
						channel.connect ();
		
						try {
							checkAck (in);
							int size = (int) file.length ();
							out.write ( ("C0644 "+size+" "+name+"-"+i+"\n").getBytes () );
							out.flush ();
							checkAck (in);
							
							byte[] buffer = new byte[4096];
							int remaining = size;
							while (remaining > 0) {
								int n = source.read (buffer, 0 , Math.min (buffer.length, remaining));
								if (n < 0) break;
								out.write (buffer, 0, n);
								remaining -= n;
							}
							out.flush ();
							
							out.write (0);
							out.flush ();
							checkAck (in);
							out.write ("E\n".getBytes ());
							out.flush ();
		
							System.err.println ("transferred "+(size-remaining)+" of "+size+" in "+path+" to ~/"+name+"-"+i+"@"+host);
							
							try { source.close (); } catch (IOException e) {}
							try { in.close (); } catch (IOException e) {}
							try { out.close (); } catch (IOException e) {}
						} finally {
							channel.disconnect ();
							channel = null;
						}
					} finally {
						if (session != null)
							session.disconnect ();
					}
				}
			}
			System.exit (0);

		} catch (Exception e) {
			System.out.println(e);
			System.exit (-1);
		}
		 
	}
	
	private static void checkAck (InputStream in)
		throws IOException
	{
		int code = in.read ();
		if (code == -1)
			throw new IOException ("Unexpected end of data");
		if (code == 1)
			throw new IOException ("SCP terminated with error: '"+readLine (in)+"'");
		if (code != 0)
			throw new IOException ("SCP terminated with error (code: "+code+")");
	}
	
	private static String readLine (InputStream in)
		throws IOException
	{
		StringBuffer sb = new StringBuffer ();
		while (true) {
			if (sb.length () > 8192)
				throw new IOException ("Remote line too long");
			int c = in.read ();
			if (c < 0)
				throw new IOException ("Remote terminated unexpectedly");
			if (c == 0xa)
				break;
			sb.append ((char) c);
		}
		return sb.toString ();
	}

}
