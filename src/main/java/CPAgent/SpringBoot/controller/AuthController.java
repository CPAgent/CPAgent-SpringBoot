package CPAgent.SpringBoot.controller;

import CPAgent.SpringBoot.model.User;
import CPAgent.SpringBoot.security.JwtUtil;
import CPAgent.SpringBoot.service.RefreshTokenService;
import CPAgent.SpringBoot.service.UserService;
import lombok.Data;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;

    public AuthController(UserService userService, JwtUtil jwtUtil, RefreshTokenService refreshTokenService) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest req) {
        User u = userService.register(req.getEmail(), req.getUsername(), req.getPassword());
        return ResponseEntity.ok(Map.of("id", u.getId(), "username", u.getUsername()));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req) {
        return userService.authenticate(req.getEmail(), req.getPassword())
                .map(u -> {
                    String access = jwtUtil.generateToken(u.getEmail());
                    String refresh = jwtUtil.generateRefreshToken(u.getEmail());
                    // persist refresh token
                    long expiresMs = jwtUtil.getRefreshValidityMillis();
                    refreshTokenService.create(refresh, u.getEmail(), java.time.Instant.now().plusMillis(expiresMs));
                    return ResponseEntity.ok(Map.of("access_token", access, "refresh_token", refresh));
                })
                .orElseGet(() -> ResponseEntity.status(401).body(Map.of("error", "invalid credentials")));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody Map<String, String> body) {
        String rt = body.get("refresh_token");
        if (rt == null)
            return ResponseEntity.badRequest().body(Map.of("error", "missing refresh_token"));

        return refreshTokenService.findByToken(rt)
                .filter(token -> token.getExpiresAt().isAfter(java.time.Instant.now()))
                .map(token -> {
                    // validate token signature as well
                    if (!jwtUtil.validateToken(rt, "refresh")) {
                        refreshTokenService.deleteByToken(rt);
                        return ResponseEntity.status(401).body(Map.of("error", "invalid refresh token"));
                    }
                    String email = jwtUtil.extractUsername(rt);
                    String newAccess = jwtUtil.generateToken(email);
                    return ResponseEntity.ok(Map.of("access_token", newAccess));
                })
                .orElseGet(
                        () -> ResponseEntity.status(401).body(Map.of("error", "refresh token expired or not found")));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody Map<String, String> body) {
        String rt = body.get("refresh_token");
        if (rt == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "missing refresh_token"));
        }
        boolean deleted = refreshTokenService.deleteIfExists(rt);
        if (deleted) {
            return ResponseEntity.ok(Map.of("status", "logged out"));
        } else {
            return ResponseEntity.status(404).body(Map.of("error", "refresh token not found"));
        }
    }

    @Data
    public static class RegisterRequest {
        private String email;
        private String username;
        private String password;
    }

    @Data
    public static class LoginRequest {
        private String email;
        private String password;
    }
}
