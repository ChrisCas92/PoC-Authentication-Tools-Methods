package com.windows_kerberos.model;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

public class UserDetails implements Serializable {
  private static final long serialVersionUID = 1L;

  private String username;
  private String displayName;
  private String email;
  private Set<String> groups = new HashSet<>();

  // Default constructor required for serialization
  public UserDetails() {
  }

  public static long getSerialversionuid() {
    return serialVersionUID;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getDisplayName() {
    return displayName;
  }

  public void setDisplayName(String displayName) {
    this.displayName = displayName;
  }

  public String getEmail() {
    return email;
  }

  public void setEmail(String email) {
    this.email = email;
  }

  public Set<String> getGroups() {
    return groups;
  }

  public void setGroups(Set<String> groups) {
    this.groups = groups;
  }

  @Override
  public String toString() {
    return "UserDetails{" +
        "username='" + username + '\'' +
        ", displayName='" + displayName + '\'' +
        ", email='" + email + '\'' +
        ", groups=" + groups +
        '}';
  }
}