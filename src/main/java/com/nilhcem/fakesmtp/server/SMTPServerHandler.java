package com.nilhcem.fakesmtp.server;

import com.nilhcem.fakesmtp.core.exception.BindPortException;
import com.nilhcem.fakesmtp.core.exception.OutOfRangePortException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.subethamail.smtp.helper.SimpleMessageListenerAdapter;
import org.subethamail.smtp.server.SMTPServer;

/**
 * Starts and stops the SMTP server.
 *
 * @author Nilhcem
 * @since 1.0
 */
public class SMTPServerHandler {
	private static SMTPServerHandler INSTANCE;

	private static final Logger LOGGER = LoggerFactory.getLogger(SMTPServerHandler.class);
	private final MailSaver mailSaver = new MailSaver();
	private final MailListener myListener = new MailListener(mailSaver);
	private final SMTPServer smtpServer;
	private final SSLContext sslContext;

	public static synchronized SMTPServerHandler getInstance(String type, String keystorePath, String password) {
		if (INSTANCE == null) {
			INSTANCE = new SMTPServerHandler(type, keystorePath, password);
		}
		return INSTANCE;
	}

	public static synchronized SMTPServerHandler getInstance(String type) {
		if (INSTANCE == null) {
			INSTANCE = new SMTPServerHandler(type, null, null);
		}
		return INSTANCE;
	}

	public static synchronized SMTPServerHandler getInstance() {
		return INSTANCE;
	}

	SMTPServerHandler(String type, String keystorePath, String password) {
		try {
			// Load keystore with your certificate
			InputStream keyStoreIS;
			char[] keyStorePassphrase;
			if (keystorePath == null) {
				keyStoreIS = getClass().getClassLoader().getResourceAsStream("keystore.jks");
				keyStorePassphrase = "qwe".toCharArray();
			} else {
				keyStoreIS = new FileInputStream(keystorePath);
				keyStorePassphrase = password.toCharArray();
			}
			KeyStore ksKeys = KeyStore.getInstance("JKS");
			ksKeys.load(keyStoreIS, keyStorePassphrase);

			// Initialize KeyManager
			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			kmf.init(ksKeys, keyStorePassphrase);

			sslContext = SSLContext.getInstance("TLSv1.2");
			sslContext.init(kmf.getKeyManagers(), null, null);

			if ("SSL".equals(type)) {
				// SSL
				smtpServer = new SMTPServer(new SimpleMessageListenerAdapter(myListener), new SMTPAuthHandlerFactory()) {
					@Override
					protected ServerSocket createServerSocket() throws IOException {
						// This forces the main listening socket to be SSL
						SSLServerSocket socket = (SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket(
							getPort(), getBacklog(), getBindAddress());
						socket.setUseClientMode(false); // Server mode
						return socket;
					}
				};
			} else {
				// TLS / NONE
				smtpServer = new SMTPServer(new SimpleMessageListenerAdapter(myListener), new SMTPAuthHandlerFactory()) {
					@Override
					public SSLSocket createSSLSocket(Socket socket) throws IOException {
						InetSocketAddress remoteAddress = (InetSocketAddress) socket.getRemoteSocketAddress();
						SSLSocketFactory sf = sslContext.getSocketFactory();
						SSLSocket s = (SSLSocket) sf.createSocket(socket, remoteAddress.getHostName(), socket.getPort(), true);

						s.setUseClientMode(false);
						s.setEnabledProtocols(s.getSupportedProtocols());
						s.setEnabledCipherSuites(s.getSupportedCipherSuites());

						return s;
					}
				};

				// TLS only
				// smtpServer.setRequireTLS(true);
			}

			smtpServer.setEnableTLS(true);

		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Starts the server on the port and address specified in parameters.
	 *
	 * @param port        the SMTP port to be opened.
	 * @param bindAddress the address to bind to. null means bind to all.
	 * @throws BindPortException        when the port can't be opened.
	 * @throws OutOfRangePortException  when port is out of range.
	 * @throws IllegalArgumentException when port is out of range.
	 */
	public void startServer(int port, InetAddress bindAddress) throws BindPortException, OutOfRangePortException {
		LOGGER.debug("Starting server on port {}", port);
		try {
			smtpServer.setBindAddress(bindAddress);
			smtpServer.setPort(port);
			smtpServer.start();
		} catch (RuntimeException exception) {
			if (exception.getMessage().contains("BindException")) { // Can't open port
				LOGGER.error("{}. Port {}", exception.getMessage(), port);
				throw new BindPortException(exception, port);
			} else if (exception.getMessage().contains("out of range")) { // Port out of range
				LOGGER.error("Port {} out of range.", port);
				throw new OutOfRangePortException(exception, port);
			} else { // Unknown error
				LOGGER.error("", exception);
				throw exception;
			}
		}
	}

	/**
	 * Stops the server.
	 * <p>
	 * If the server is not started, does nothing special.
	 * </p>
	 */
	public void stopServer() {
		if (smtpServer.isRunning()) {
			LOGGER.debug("Stopping server");
			smtpServer.stop();
		}
	}

	/**
	 * Returns the {@code MailSaver} object.
	 *
	 * @return the {@code MailSaver} object.
	 */
	public MailSaver getMailSaver() {
		return mailSaver;
	}

	/**
	 * Returns the {@code SMTPServer} object.
	 *
	 * @return the {@code SMTPServer} object.
	 */
	public SMTPServer getSmtpServer() {
		return smtpServer;
	}
}
