package com.niladri.authify.to;

public record ResetPasswordRequest(
        String newPassword,
        String email,
        String otp
) {
}
