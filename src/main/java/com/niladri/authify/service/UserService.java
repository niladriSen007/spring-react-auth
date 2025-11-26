package com.niladri.authify.service;

import com.niladri.authify.mapper.Mapper;
import com.niladri.authify.models.User;
import com.niladri.authify.repository.UserRepository;
import com.niladri.authify.to.ProfileRequest;
import com.niladri.authify.to.ProfileResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.concurrent.ThreadLocalRandom;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    public ProfileResponse createUserProfile(ProfileRequest profileRequest) {
        var user = userRepository.findByEmail(profileRequest.email());
        if (user.isPresent()) {
            throw new IllegalArgumentException("User with email " + profileRequest.email() + " already exists.");
        }
        var newUser = new User();
        newUser.setName(profileRequest.name());
        newUser.setEmail(profileRequest.email());
        newUser.setRoles(profileRequest.roles());
        newUser.setPassword(passwordEncoder.encode(profileRequest.password())); // In real applications, ensure to hash
        // the password before saving
        newUser.setAccountVerified(false);

        var savedUser = userRepository.save(newUser);

        log.info("Created new user with email: {}", savedUser.getEmail());
        return Mapper.mapToProfileResponse(savedUser);
    }

    public ProfileResponse getUserProfile(String email) {
        var user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User with email " + email + " not found."));
        return Mapper.mapToProfileResponse(user);
    }

    public void sendResetOtp(String email) {
        var user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User with email " + email + " not found."));

        String otp = String.valueOf(ThreadLocalRandom.current().nextInt(100000, 999999));
        long expiryTime = System.currentTimeMillis() + 5 * 60 * 1000;
        user.setResetOtp(otp);
        user.setResetOtpExpireAt(expiryTime);

        try {
            emailService.sendResetOtpEmail(user.getEmail(), otp);
        } catch (Exception e) {
            log.error("Failed to send OTP email to {}", email, e);
        }
    }

    public void resetPassword(String email, String otp, String newPassword) {
        var user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User with email " + email + " not found."));

        if (user.getResetOtp() == null || !user.getResetOtp().equals(otp)) {
            throw new IllegalArgumentException("Invalid OTP.");
        }

        if (System.currentTimeMillis() > user.getResetOtpExpireAt()) {
            throw new IllegalArgumentException("OTP has expired.");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setResetOtp(null);
        user.setResetOtpExpireAt(0L);

        userRepository.save(user);
        log.info("Password reset successfully for user with email: {}", email);
    }

    public void sendOtp(String email) {
        var user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User with email " + email + " not found."));

        String otp = String.valueOf(ThreadLocalRandom.current().nextInt(100000, 999999));
        long expiryTime = System.currentTimeMillis() + 10 * 60 * 1000;
        user.setVerifyOtp(otp);
        user.setVerifyOtpExpireAt(expiryTime);

        try {
            emailService.sendOtpEmail(user.getEmail(), otp);
        } catch (Exception e) {
            log.error("Failed to send OTP email to {}", email, e);
        }
    }


    public void verifyOtp(String email, String otp) {
        var user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User with email " + email + " not found."));

        if (user.getVerifyOtp() == null || !user.getVerifyOtp().equals(otp)) {
            throw new IllegalArgumentException("Invalid OTP.");
        }

        if (System.currentTimeMillis() > user.getVerifyOtpExpireAt()) {
            throw new IllegalArgumentException("OTP has expired.");
        }

        user.setAccountVerified(true);
        user.setVerifyOtp(null);
        user.setVerifyOtpExpireAt(0L);

        userRepository.save(user);
        log.info("Account verified successfully for user with email: {}", email);
    }

}
