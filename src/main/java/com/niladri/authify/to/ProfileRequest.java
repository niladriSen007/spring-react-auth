package com.niladri.authify.to;

public record ProfileRequest(String name, String email, String password, String roles) {
}
