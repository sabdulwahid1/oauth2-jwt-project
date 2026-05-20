package com.example.oauth20;

import java.util.Map;

import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final UserRepository repo;

    public UserService(UserRepository repo) {
        this.repo = repo;
    }

    public User saveOrUpdateUser(Map<String, Object> attributes) {

        String email = (String) attributes.get("email");
        String name = (String) attributes.get("name");
        String providerId = (String) attributes.get("sub");

        return repo.findByEmail(email)
        		.map(user -> {
        		    user.setName(name);

        		    if (user.getRole() == null) {  
        		        user.setRole("USER");
        		    }

        		    return repo.save(user);
        		})
                .orElseGet(() -> {
                    User user = new User();
                    user.setEmail(email);
                    user.setName(name);
                    user.setProvider("GOOGLE");
                    user.setProviderId(providerId);
                    user.setRole("USER"); //Default Role
                    return repo.save(user);
                });
    }
    
    public User getByEmail(String email) {
        return repo.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    public User save(User user) {
        return repo.save(user);
    }
}
