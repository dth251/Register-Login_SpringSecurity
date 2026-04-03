package org.example.springsecurity.security.service;


import com.example.auth.dto.request.LoginRequest;
import com.example.auth.dto.request.RefreshTokenRequest;
import com.example.auth.dto.request.RegisterRequest;
import com.example.auth.dto.response.AuthResponse;
import com.example.auth.entity.*;
import com.example.auth.exception.AuthException;
import com.example.auth.repository.RoleRepository;
import com.example.auth.repository.TokenBlacklistRepository;
import com.example.auth.repository.UserRepository;
import com.example.auth.security.jwt.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository            userRepository;
    private final RoleRepository            roleRepository;
    private final TokenBlacklistRepository  blacklistRepository;
    private final PasswordEncoder           passwordEncoder;
    private final JwtService                jwtService;
    private final RefreshTokenService       refreshTokenService;
    private final AuthenticationManager     authenticationManager;

    // ===================== REGISTER =====================
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new AuthException("Username '" + request.getUsername() + "' đã tồn tại");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new AuthException("Email '" + request.getEmail() + "' đã được sử dụng");
        }

        // Mặc định gán ROLE_USER
        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                .orElseThrow(() -> new RuntimeException("Role ROLE_USER chưa được khởi tạo trong DB"));

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(Set.of(userRole))
                .build();

        userRepository.save(user);
        log.info("User mới đã đăng ký: {} với roles: {}", user.getUsername(), user.getRoleNames());

        return buildAuthResponse(user);
    }

    // ===================== LOGIN =====================
    @Transactional
    public AuthResponse login(LoginRequest request) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(),
                            request.getPassword()
                    )
            );
        } catch (BadCredentialsException e) {
            throw new AuthException("Username hoặc password không đúng");
        }

        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new AuthException("User không tồn tại"));

        log.info("User đăng nhập thành công: {} | roles: {}", user.getUsername(), user.getRoleNames());
        return buildAuthResponse(user);
    }

    // ===================== REFRESH TOKEN =====================
    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        RefreshToken refreshToken = refreshTokenService.verifyRefreshToken(request.getRefreshToken());
        User user = refreshToken.getUser();

        String newAccessToken       = jwtService.generateAccessToken(user);
        RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(user);

        log.debug("Refresh token thành công cho user: {}", user.getUsername());

        return buildAuthResponseWithTokens(user, newAccessToken, newRefreshToken.getToken());
    }

    // ===================== LOGOUT =====================
    @Transactional
    public void logout(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new AuthException("Token không hợp lệ");
        }

        String accessToken = authHeader.substring(7);

        TokenBlacklist blacklistEntry = TokenBlacklist.builder()
                .token(accessToken)
                .expiredAt(jwtService.extractExpirationAsInstant(accessToken))
                .build();
        blacklistRepository.save(blacklistEntry);

        String username = jwtService.extractUsername(accessToken);
        userRepository.findByUsername(username).ifPresent(refreshTokenService::revokeAllUserTokens);

        log.info("User đăng xuất thành công: {}", username);
    }

    // ===================== HELPERS =====================

    private AuthResponse buildAuthResponse(User user) {
        String accessToken        = jwtService.generateAccessToken(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);
        return buildAuthResponseWithTokens(user, accessToken, refreshToken.getToken());
    }

    private AuthResponse buildAuthResponseWithTokens(User user, String accessToken, String refreshTokenStr) {
        // Trả về danh sách roles (VD: "ROLE_USER, ROLE_ADMIN")
        String roles = user.getRoleNames();

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshTokenStr)
                .tokenType("Bearer")
                .username(user.getUsername())
                .email(user.getEmail())
                .roles(roles)
                .expiresIn(jwtService.getAccessTokenExpiration())
                .build();
    }
}
