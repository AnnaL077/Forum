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
import telran.java47.post.dao.PostRepository;
import telran.java47.post.model.Post;

@Component
@Order(70)
@RequiredArgsConstructor
public class PostOwnerOrModerator implements Filter {

	final PostRepository postRepository;
	final UserAccountRepository userAccountRepository;
	
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
			String postID = path.substring(path.lastIndexOf("/") + 1);
			Post post = postRepository.findById(postID).orElse(null);
			if (post == null) {
				response.sendError(401, "post is not founded");
				return;
			}

			if (!(checkOwner(post, request.getUserPrincipal().getName())||checkModerator(request.getUserPrincipal().getName()))) {
				response.sendError(403, "not enough rights");
				return;
			}
		}
		chain.doFilter(request, response);
	}



	private boolean checkEndPoint(String method, String path) {

		return ("DELETE".equalsIgnoreCase(method) && path.matches("/forum/post/\\w+/?"));
	}

	private boolean checkOwner(Post post, String login) {
		
		return login.equalsIgnoreCase(post.getAuthor());
	}
	
	private boolean checkModerator(String login) {
		
		UserAccount userAccount = userAccountRepository.findById(login).orElse(null);
		return userAccount.getRoles().contains("MODERATOR");
	}


}
