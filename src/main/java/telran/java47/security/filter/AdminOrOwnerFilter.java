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

import lombok.RequiredArgsConstructor;
import telran.java47.accounting.dao.UserAccountRepository;
import telran.java47.accounting.model.UserAccount;


@Component
@Order(40)
@RequiredArgsConstructor
public class AdminOrOwnerFilter implements Filter {

	final UserAccountRepository userAccountRepository;
	
	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		if (checkEndPoint(request.getMethod(), request.getServletPath())) {
			
			if (!(checkAdmin(request.getUserPrincipal().getName()) 
					|| checkOwner(request.getUserPrincipal().getName(), request.getServletPath().substring(request.getServletPath().lastIndexOf("/") + 1)))) {
				response.sendError(403, "not enough rights");
				return;
			}
		}
		chain.doFilter(request, response);
	}
	

	private boolean checkEndPoint(String method, String path) {
		return ("DELETE".equalsIgnoreCase(method) && path.matches("/account/user/\\w+/?"));
	}
	
	private boolean checkAdmin(String login) {
		UserAccount userAccount = userAccountRepository.findById(login).orElse(null);
		return userAccount.getRoles().contains("ADMINISTRATOR");
	}
	
	private boolean checkOwner(String login, String loginPath) {
		return login.equalsIgnoreCase(loginPath);
	}

}
