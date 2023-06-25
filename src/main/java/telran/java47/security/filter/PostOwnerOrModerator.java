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
import telran.java47.security.model.Roles;
import telran.java47.security.model.User;

@Component
@Order(60)
@RequiredArgsConstructor
public class PostOwnerOrModerator implements Filter {

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
				response.sendError(401,CommentsOfError.POST_IS_NOT_FOUNDED.toString());
				return;
			}
			User user = (User) request.getUserPrincipal(); 
			if (!(user.getName().equalsIgnoreCase(post.getAuthor()) || user.getRoles().contains(Roles.MODERATOR))) {
				response.sendError(403, CommentsOfError.NOT_ENOUTH_RIGHTS.toString());
				return;
			}
		}
		chain.doFilter(request, response);
	}



	private boolean checkEndPoint(String method, String path) {

		return (HttpMethod.DELETE.name().equalsIgnoreCase(method) && path.matches("/forum/post/\\w+/?"));
	}



}
