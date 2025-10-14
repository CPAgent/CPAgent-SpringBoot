package CPAgent.SpringBoot.service;

import CPAgent.SpringBoot.model.User;
import CPAgent.SpringBoot.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User register(String username, String rawPassword) {
        String hashed = passwordEncoder.encode(rawPassword);
        User user = new User();
        user.setUsername(username);
        user.setPassword(hashed);
        user.setRoles("ROLE_USER");
        return userRepository.save(user);
    }

    public Optional<User> authenticate(String username, String rawPassword) {
        Optional<User> u = userRepository.findByUsername(username);
        if (u.isPresent()) {
            if (passwordEncoder.matches(rawPassword, u.get().getPassword())) {
                return u;
            }
        }
        return Optional.empty();
    }
}
