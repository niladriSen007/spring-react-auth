package com.niladri.authify.mapper;

import com.niladri.authify.models.User;
import com.niladri.authify.to.ProfileRequest;
import com.niladri.authify.to.ProfileResponse;

public class Mapper {

    public static User mapToUser(ProfileRequest profileRequest) {
        return User.builder()
                .name(profileRequest.name())
                .email(profileRequest.email())
                .password(profileRequest.password())
                .roles(profileRequest.roles())
                .build();
    }

    public static ProfileResponse mapToProfileResponse(User user) {
        return ProfileResponse.builder().
                userId(user.getUserId())
                .name(user.getName())
                .email(user.getEmail())
                .isAccountVerified(user.isAccountVerified())
                .build();
    }
}
