package org.example.springsecurity.controller;


import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.springsecurity.dto.request.LoginRequest;
import org.example.springsecurity.dto.request.RefreshTokenRequest;
import org.example.springsecurity.dto.request.RegisterRequest;
import org.example.springsecurity.dto.response.ApiResponse;
import org.example.springsecurity.dto.response.AuthResponse;
import org.example.springsecurity.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * POST /api/auth/register
     * Đăng ký tài khoản mới (role mặc định: USER)
     */
    @PostMapping("/register")
    public ResponseEntity<ApiResponse<AuthResponse>> register(
            @Valid @RequestBody RegisterRequest request) {
        AuthResponse response = authService.register(request);
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(ApiResponse.success("Đăng ký thành công", response));
    }

    /**
     * POST /api/auth/login
     * Đăng nhập — trả về access token + refresh token
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(
            @Valid @RequestBody LoginRequest request) {
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(ApiResponse.success("Đăng nhập thành công", response));
    }

    /**
     * POST /api/auth/refresh
     * Lấy access token mới bằng refresh token (Refresh Token Rotation)
     */
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<AuthResponse>> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request) {
        AuthResponse response = authService.refreshToken(request);
        return ResponseEntity.ok(ApiResponse.success("Refresh token thành công", response));
    }

    /**
     * POST /api/auth/logout
     * Đăng xuất — blacklist access token + revoke refresh tokens
     */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            @RequestHeader("Authorization") String authHeader) {
        authService.logout(authHeader);
        return ResponseEntity.ok(ApiResponse.success("Đăng xuất thành công"));
    }
}
