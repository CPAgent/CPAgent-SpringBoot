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

    public User register(String email, String username, String rawPassword) {
        String hashed = passwordEncoder.encode(rawPassword);
        User user = new User();
        user.setEmail(email);
        user.setUsername(username);
        user.setPassword(hashed);
        return userRepository.save(user);
    }

    public Optional<User> authenticate(String email, String rawPassword) {
        Optional<User> u = userRepository.findByEmail(email);
        if (u.isPresent()) {
            if (passwordEncoder.matches(rawPassword, u.get().getPassword())) {
                return u;
            }
        }
        return Optional.empty();
    }
}
