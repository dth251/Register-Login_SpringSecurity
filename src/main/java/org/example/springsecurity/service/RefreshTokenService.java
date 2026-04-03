package org.example.springsecurity.service;



import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.springsecurity.entity.RefreshToken;
import org.example.springsecurity.entity.User;
import org.example.springsecurity.exception.TokenException;
import org.example.springsecurity.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    @Value("${app.jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    private final RefreshTokenRepository refreshTokenRepository;

    @Transactional
    public RefreshToken createRefreshToken(User user) {
        // Revoke tất cả refresh token cũ của user trước khi tạo mới
        refreshTokenRepository.revokeAllUserTokens(user);

        RefreshToken refreshToken = RefreshToken.builder()
                .token(UUID.randomUUID().toString())
                .user(user)
                .expiryDate(Instant.now().plusMillis(refreshTokenExpiration))
                .revoked(false)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    @Transactional(readOnly = true)
    public RefreshToken verifyRefreshToken(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new TokenException("Refresh token không tồn tại"));

        if (refreshToken.isRevoked()) {
            throw new TokenException("Refresh token đã bị thu hồi");
        }

        if (refreshToken.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(refreshToken);
            throw new TokenException("Refresh token đã hết hạn, vui lòng đăng nhập lại");
        }

        return refreshToken;
    }

    @Transactional
    public void revokeAllUserTokens(User user) {
        refreshTokenRepository.revokeAllUserTokens(user);
        log.debug("Đã revoke tất cả refresh token của user: {}", user.getUsername());
    }

    @Transactional
    public void cleanupExpiredTokens() {
        refreshTokenRepository.deleteAllExpiredTokens(Instant.now());
        log.info("Đã xóa các refresh token hết hạn");
    }
}
