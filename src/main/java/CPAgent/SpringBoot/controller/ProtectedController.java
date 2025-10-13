package CPAgent.SpringBoot.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class ProtectedController {

    @GetMapping("/protected")
    public Map<String, Object> protectedEndpoint(Authentication authentication) {
        String principal = (authentication != null) ? authentication.getName() : "anonymous";
        return Map.of("message", "This is a protected resource", "user", principal);
    }
}
