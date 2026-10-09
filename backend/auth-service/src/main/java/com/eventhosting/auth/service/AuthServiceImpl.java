package com.eventhosting.auth.service;

import com.eventhosting.auth.dto.*;
import com.eventhosting.auth.exception.InvalidTokenException;
import com.eventhosting.auth.exception.ResourceAlreadyExistsException;
import com.eventhosting.auth.model.Role;
import com.eventhosting.auth.model.User;
import com.eventhosting.auth.repository.UserRepository;
import com.eventhosting.auth.security.JwtService;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Override
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        log.info("Attempting registration for email: {}", request.getEmail());

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new ResourceAlreadyExistsException("Email already registered: " + request.getEmail());
        }

        if (userRepository.existsByUsername(request.getUsername())) {
            throw new ResourceAlreadyExistsException("Username already taken: " + request.getUsername());
        }

        Role assignedRole = request.getRole() != null ? request.getRole() : Role.ROLE_USER;

        User user = User.builder()
                .fullName(request.getFullName().trim())
                .username(request.getUsername().trim().toLowerCase())
                .email(request.getEmail().trim().toLowerCase())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(assignedRole)
                .enabled(true)
                .build();

        User savedUser = userRepository.save(user);
        log.info("User registered successfully with ID: {}", savedUser.getId());

        String jwtToken = jwtService.generateToken(savedUser);
        String refreshToken = jwtService.generateRefreshToken(savedUser);

        return AuthResponse.builder()
                .token(jwtToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtService.getExpirationTime())
                .user(mapToUserDto(savedUser))
                .build();
    }

    @Override
    @Transactional(readOnly = true)
    public AuthResponse login(LoginRequest request) {
        log.info("Authenticating user: {}", request.getEmail());

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail().trim().toLowerCase(),
                        request.getPassword()
                )
        );

        User user = userRepository.findByEmail(request.getEmail().trim().toLowerCase())
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + request.getEmail()));

        String jwtToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        log.info("User {} authenticated successfully", user.getEmail());

        return AuthResponse.builder()
                .token(jwtToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtService.getExpirationTime())
                .user(mapToUserDto(user))
                .build();
    }

    @Override
    @Transactional(readOnly = true)
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();
        if (!jwtService.validateToken(refreshToken)) {
            throw new InvalidTokenException("Invalid or expired refresh token");
        }

        String email = jwtService.extractUsername(refreshToken);
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));

        String newAccessToken = jwtService.generateToken(user);

        return AuthResponse.builder()
                .token(newAccessToken)
                .refreshToken(refreshToken) // Retain original refresh token
                .tokenType("Bearer")
                .expiresIn(jwtService.getExpirationTime())
                .user(mapToUserDto(user))
                .build();
    }

    @Override
    @Transactional(readOnly = true)
    public TokenValidationResponse validateToken(String token) {
        if (token == null || !jwtService.validateToken(token)) {
            return TokenValidationResponse.builder().valid(false).build();
        }

        Claims claims = jwtService.extractAllClaims(token);
        String email = claims.getSubject();
        Long userId = claims.get("userId", Long.class);
        String username = claims.get("username", String.class);
        String role = claims.get("role", String.class);

        return TokenValidationResponse.builder()
                .valid(true)
                .userId(userId)
                .email(email)
                .username(username)
                .role(role)
                .build();
    }

    @Override
    @Transactional(readOnly = true)
    public UserDto getCurrentUser(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));
        return mapToUserDto(user);
    }

    private UserDto mapToUserDto(User user) {
        return UserDto.builder()
                .id(user.getId())
                .fullName(user.getFullName())
                .username(user.getDisplayUsername())
                .email(user.getEmail())
                .role(user.getRole())
                .enabled(user.isEnabled())
                .createdAt(user.getCreatedAt())
                .build();
    }
}
