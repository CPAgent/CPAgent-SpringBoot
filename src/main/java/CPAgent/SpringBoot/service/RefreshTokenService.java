package CPAgent.SpringBoot.service;

import CPAgent.SpringBoot.model.RefreshToken;
import CPAgent.SpringBoot.repository.RefreshTokenRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;

@Service
public class RefreshTokenService {
    private final RefreshTokenRepository repo;

    public RefreshTokenService(RefreshTokenRepository repo) {
        this.repo = repo;
    }

    public RefreshToken create(String token, String email, Instant expiresAt) {
        RefreshToken rt = new RefreshToken();
        rt.setToken(token);
        rt.setEmail(email);
        rt.setExpiresAt(expiresAt);
        return repo.save(rt);
    }

    public Optional<RefreshToken> findByToken(String token) {
        return repo.findByToken(token);
    }

    public void deleteByToken(String token) {
        repo.deleteByToken(token);
    }

    public boolean deleteIfExists(String token) {
        return repo.findByToken(token).map(t -> {
            repo.delete(t);
            return true;
        }).orElse(false);
    }
}
