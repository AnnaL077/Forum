package telran.java47.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class AuthorizationConfiguration {

	@Bean
	public SecurityFilterChain configure(HttpSecurity http) throws Exception {
		http.httpBasic();
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
	
//		http.authorizeRequests(authorize -> authorize
//				.mvcMatchers("/account/register", "/forum/posts**")
//					.permitAll()
//				.mvcMatchers(HttpMethod.PUT, "/account/password")
//					.authenticated()
//				.mvcMatchers("/account/user/{login}/role/{role}")
//					.access("hasRole('ADMINISTRATOR') and hasRole('LIFE')")
//				.mvcMatchers(HttpMethod.PUT, "/account/user/{login}")
//					.access("#login == authentication.name and hasRole('LIFE')")
//				.mvcMatchers(HttpMethod.DELETE, "/account/user/{login}")
//					.access("(#login == authentication.name and hasRole('LIFE')) or (hasRole('ADMINISTRATOR') and hasRole('LIFE'))")
//				.mvcMatchers(HttpMethod.POST, "/forum/post/{author}")
//					.access("#author == authentication.name and hasRole('LIFE')")
//				.mvcMatchers(HttpMethod.PUT, "/forum/post/{id}/comment/{author}")
//					.access("#author == authentication.name and hasRole('LIFE')")
//				.mvcMatchers(HttpMethod.PUT, "/forum/post/{id}")
//					.access("@customSecurity.checkPostAuthor(#id, authentication.name) and hasRole('LIFE')")
//				.mvcMatchers(HttpMethod.DELETE, "/forum/post/{id}")
//					.access("(@customSecurity.checkPostAuthor(#id, authentication.name) and hasRole('LIFE')) or (hasRole('MODERATOR') and hasRole('LIFE'))")
//				.anyRequest()
//					.hasRole("LIFE")
//					);
		
		return http.build();
	}
}
