package com.example.oauth20;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository repo;

    private final long REFRESH_EXPIRY_SECONDS = 7 * 24 * 60 * 60;

    public RefreshTokenService(RefreshTokenRepository repo) {
        this.repo = repo;
    }

    @Transactional   // 🔥 ADD THIS
    public RefreshToken create(String email) {
        repo.deleteByEmail(email);

        RefreshToken rt = new RefreshToken();
        rt.setToken(UUID.randomUUID().toString());
        rt.setEmail(email);
        rt.setExpiryDate(Instant.now().plusSeconds(REFRESH_EXPIRY_SECONDS));

        return repo.save(rt);
    }

    public RefreshToken validate(String token) {
        RefreshToken rt = repo.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        if (rt.getExpiryDate().isBefore(Instant.now())) {
            repo.delete(rt);
            throw new RuntimeException("Refresh token expired");
        }

        return rt;
    }

    @Transactional   // 🔥 ALSO ADD HERE
    public void delete(String token) {
        repo.findByToken(token).ifPresent(repo::delete);
    }
}