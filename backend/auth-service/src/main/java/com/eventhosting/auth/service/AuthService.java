package com.eventhosting.auth.service;

import com.eventhosting.auth.dto.*;

public interface AuthService {
    AuthResponse register(RegisterRequest request);
    AuthResponse login(LoginRequest request);
    AuthResponse refreshToken(RefreshTokenRequest request);
    TokenValidationResponse validateToken(String token);
    UserDto getCurrentUser(String email);
}
