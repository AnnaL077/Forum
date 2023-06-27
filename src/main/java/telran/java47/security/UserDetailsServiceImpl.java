package telran.java47.security;


import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import telran.java47.accounting.dao.UserAccountRepository;
import telran.java47.accounting.model.UserAccount;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
	
final UserAccountRepository userAccountRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		System.out.println(username);
		UserAccount userAccount = userAccountRepository.findById(username)
				.orElseThrow(() -> new UsernameNotFoundException(username));
		
		System.out.println(userAccount.getFirstName());
		List<String> roles = userAccount.getRoles()
				.stream()
				.map(r -> "ROLE_" + r)
				.toList();
		
		if (userAccount.getDatePassword().isAfter(LocalDateTime.now())) {
			roles.add("ROLE_LIFE");
		}
		userAccount.getRoles().forEach(System.out::println);
	
		return new User(username, userAccount.getPassword(), AuthorityUtils.createAuthorityList(roles.toArray(String[]::new)));
 		
	}

}
