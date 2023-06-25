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
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;

import telran.java47.security.model.CommentsOfError;
import telran.java47.security.model.Roles;
import telran.java47.security.model.User;

@Component
@Order(20)

public class RolesManagingFilter implements Filter {

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;

		if (checkEndPoint(request.getMethod(), request.getServletPath())) {
			User user = (User) request.getUserPrincipal(); 
			if (! user.getRoles().contains(Roles.ADMINISTRATOR.toString())){
				response.sendError(403, CommentsOfError.NOT_ENOUTH_RIGHTS.toString());
				return;
			}
		}
		chain.doFilter(request, response);
	}
	
	private boolean checkEndPoint(String method, String path) {
		return ((HttpMethod.PUT.name().equalsIgnoreCase(method) || HttpMethod.DELETE.name().equalsIgnoreCase(method)) && path.matches("/account/user/\\w+/role/\\w+/?"));
	}
}
