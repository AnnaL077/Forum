package telran.java47.security.context;

import telran.java47.security.model.User;

public interface SecurityContext {
	
	User addUserSession(String sessionId, User user);
	
	User removeUser(String sesionId);
	
	User getUserBySessionId(String sessionId);
	

}
