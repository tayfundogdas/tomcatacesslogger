package dk.dsa.wl.accesslogger;

import java.io.CharArrayWriter;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpSession;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.AccessLogValve;

import biz.paluch.logging.RuntimeContainer;
import biz.paluch.logging.gelf.intern.GelfMessage;
import biz.paluch.logging.gelf.intern.GelfSender;
import biz.paluch.logging.gelf.intern.GelfSenderFactory;
import biz.paluch.logging.gelf.intern.sender.DefaultGelfSenderProvider;
import biz.paluch.logging.gelf.standalone.DefaultGelfSenderConfiguration;

public class GelfAccessLogValve extends AccessLogValve {

	private final static Map<Class, String> names = Collections.unmodifiableMap(new HashMap<Class, String>() {
		{
			put(HeaderElement.class, "Header");
			put(CookieElement.class, "Cookie");
			put(ResponseHeaderElement.class, "ResponseHeader");
			put(SessionAttributeElement.class, "SessionAttribute");
			put(RemoteAddrElement.class, "RemoteAddr");
			put(LocalAddrElement.class, "LocalAddr");
			put(ByteSentElement.class, "ByteSent");
			put(ElapsedTimeElement.class, "ElapsedTime");
			put(HostElement.class, "Host");
			put(ProtocolElement.class, "Protocol");
			put(MethodElement.class, "Method");
			put(PortElement.class, "Port");
			put(QueryElement.class, "Query");
			put(RequestElement.class, "Request");
			put(FirstByteTimeElement.class, "FirstByteTime");
			put(HttpStatusCodeElement.class, "HttpStatusCode");
			put(SessionIdElement.class, "SessionId");
			put(DateAndTimeElement.class, "DateAndTime");
			put(UserElement.class, "User");
			put(RequestURIElement.class, "RequestURI");
			put(LocalServerNameElement.class, "LocalServerName");
			put(ThreadNameElement.class, "ThreadName");

		}
	});

	public static final String SYSLOG_LEVEL = "6";

	private String host = "localhost";
	private int port = DefaultGelfSenderProvider.DEFAULT_PORT;
	private GelfSender gelfSender;

	@Override
	public void log(Request request, Response response, long time) {

		if (gelfSender == null || !getState().isAvailable() || !getEnabled() || logElements == null
				|| condition != null && null != request.getRequest().getAttribute(condition)
				|| conditionIf != null && null == request.getRequest().getAttribute(conditionIf)) {
			return;
		}

		/**
		 * XXX This is a bit silly, but we want to have start and stop time and duration
		 * consistent. It would be better to keep start and stop simply in the request
		 * and/or response object and remove time (duration) from the interface.
		 */
		long start = request.getCoyoteRequest().getStartTime();
		Date date = new Date(start + time);

		GelfMessage message = new GelfMessage();
		message.setFacility(null);
		message.setHost(null);
		// message.setFullMessage(request.getMethod() + " " + request.getRequestURI());
		// message.setShortMessage(request.getMethod() + " " + request.getRequestURI());
		// message.setJavaTimestamp(start + time);
		// message.setHost(RuntimeContainer.FQDN_HOSTNAME);
		/*
		String username = "PUBLIC";
		HttpSession session = request.getSession(false);
		Object sci = session.getAttribute("SPRING_SECURITY_CONTEXT");
		if (sci != null) {
			username = sci.toString();
		}
		message.setLevel(username);
		 */
		for (int i = 0; i < logElements.length; i++) {

			String name = names.get(logElements[i].getClass());
			if (name == null) {
				continue;
			}

			// StringBuilder result = new StringBuilder(128);
			CharArrayWriter result = new CharArrayWriter(128);
			logElements[i].addElement(result, date, request, response, time);
			message.addField(name, result.toString());
		}

		gelfSender.sendMessage(message);

	}

	private void createSender() {
		DefaultGelfSenderConfiguration configuration = new DefaultGelfSenderConfiguration();
		configuration.setHost(host);
		configuration.setPort(port);

		gelfSender = GelfSenderFactory.createSender(configuration);
	}

	@Override
	protected synchronized void startInternal() throws LifecycleException {
		createSender();

		super.startInternal();
	}

	@Override
	protected synchronized void stopInternal() throws LifecycleException {
		if (gelfSender != null) {
			gelfSender.close();
			gelfSender = null;
		}
		super.stopInternal();
	}

	public String getHost() {
		return host;
	}

	public void setHost(String host) {
		this.host = host;
	}

	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
	}

}
