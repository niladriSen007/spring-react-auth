package com.niladri.authify.service;

import com.niladri.authify.mapper.Mapper;
import com.niladri.authify.models.User;
import com.niladri.authify.repository.UserRepository;
import com.niladri.authify.to.AuthRequest;
import com.niladri.authify.to.ProfileRequest;
import com.niladri.authify.to.ProfileResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public ProfileResponse createUserProfile(ProfileRequest profileRequest) {
        var user = userRepository.findByEmail(profileRequest.email());
        if (user.isPresent()) {
            throw new IllegalArgumentException("User with email " + profileRequest.email() + " already exists.");
        }
        var newUser = new User();
        newUser.setName(profileRequest.name());
        newUser.setEmail(profileRequest.email());
        newUser.setRoles(profileRequest.roles());
        newUser.setPassword(passwordEncoder.encode(profileRequest.password())); // In real applications, ensure to hash the password before saving
        newUser.setAccountVerified(false);

        var savedUser = userRepository.save(newUser);

        log.info("Created new user with email: {}", savedUser.getEmail());
        return Mapper.mapToProfileResponse(savedUser);
    }

    public User login(AuthRequest authRequest) {
        var user = userRepository.findByEmail(authRequest.email());
        if (user.isEmpty() || !user.get().getPassword().equals(authRequest.password())) {
            throw new IllegalArgumentException("Invalid email or password.");
        }
        return user.get();
    }
}
