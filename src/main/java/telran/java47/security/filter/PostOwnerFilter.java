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

import lombok.RequiredArgsConstructor;
import telran.java47.post.dao.PostRepository;
import telran.java47.post.model.Post;
import telran.java47.security.model.CommentsOfError;

@Component
@Order(50)
@RequiredArgsConstructor
public class PostOwnerFilter implements Filter {

	final PostRepository postRepository;
	
	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		if (checkEndPoint(request.getMethod(), request.getServletPath())) {
			String path = request.getServletPath();
			String postID = path.split("/")[path.split("/").length - 1];
			Post post = postRepository.findById(postID).orElse(null);
			if (post == null) {
				response.sendError(401, CommentsOfError.POST_IS_NOT_FOUNDED.toString());
				return;
			}

			if (!request.getUserPrincipal().getName().equalsIgnoreCase(post.getAuthor())) {
				response.sendError(403, CommentsOfError.NOT_ENOUTH_RIGHTS.toString());
				return;
			}
		}
		chain.doFilter(request, response);
	}

	private boolean checkEndPoint(String method, String path) {
		
		return (HttpMethod.PUT.name().equalsIgnoreCase(method) && path.matches("/forum/post/\\w+/?"));
	}

}
