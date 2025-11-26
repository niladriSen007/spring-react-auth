package com.niladri.authify.to;

public interface IProfile {
  String getUserId();
  String getName();
  String getEmail();
  boolean isAccountVerified();
  String getRoles();
}
