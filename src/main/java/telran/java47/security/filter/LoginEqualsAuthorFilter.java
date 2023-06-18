package telran.java47.security.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

@Component
@Order(50)
public class LoginEqualsAuthorFilter implements Filter {

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;

		if (checkEndPoint(request.getMethod(), request.getServletPath())) {
			String path = request.getServletPath();
			if (path.lastIndexOf("/", 0) == path.length() - 1 ) {
				path = path.substring(0, path.length() - 2);
			}
			String login = path.substring(path.lastIndexOf("/") + 1);
			if (!request.getUserPrincipal().getName().equalsIgnoreCase(login)) {
				response.sendError(403, "not enough rights");
				return;
			}
		}
		chain.doFilter(request, response);
	}

	private boolean checkEndPoint(String method, String path) {
		
		return (("POST".equalsIgnoreCase(method) && path.matches("/forum/post/\\w+/?"))
				|| ("PUT".equalsIgnoreCase(method) && path.matches("/forum/post/\\w+/comment/\\w+/?")));
	}

}
