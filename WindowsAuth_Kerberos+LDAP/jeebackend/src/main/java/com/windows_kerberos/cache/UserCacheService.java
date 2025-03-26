package com.windows_kerberos.cache;

import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.enterprise.context.ApplicationScoped;

import com.windows_kerberos.model.UserDetails;

@ApplicationScoped
public class UserCacheService {
  private static final Logger LOGGER = Logger.getLogger(UserCacheService.class.getName());

  // Simple in-memory cache using ConcurrentHashMap
  private ConcurrentHashMap<String, CacheEntry> userCache;

  // Cache entry expiration time in milliseconds (15 minutes)
  private static final long CACHE_EXPIRY_MS = 15 * 60 * 1000;

  @PostConstruct
  public void initialize() {
    LOGGER.info("Initializing user cache service");
    userCache = new ConcurrentHashMap<>();
  }

  @PreDestroy
  public void shutdown() {
    LOGGER.info("Shutting down user cache service");
    if (userCache != null) {
      userCache.clear();
      userCache = null;
    }
  }

  /**
   * Retrieves a user from the cache by username.
   * 
   * @param username The username to look up
   * @return The cached UserDetails, or null if not in cache or entry expired
   */
  public UserDetails getUser(String username) {
    if (userCache == null) {
      return null;
    }

    CacheEntry entry = userCache.get(username);
    if (entry == null) {
      return null;
    }

    // Check if the cache entry has expired
    if (isExpired(entry)) {
      userCache.remove(username);
      return null;
    }

    return entry.getUserDetails();
  }

  /**
   * Stores a user in the cache.
   * 
   * @param username    The username to use as a key
   * @param userDetails The user details to cache
   */
  public void putUser(String username, UserDetails userDetails) {
    if (userCache == null || userDetails == null) {
      return;
    }

    CacheEntry entry = new CacheEntry(userDetails);
    userCache.put(username, entry);
  }

  /**
   * Removes a user from the cache.
   * 
   * @param username The username to remove
   */
  public void removeUser(String username) {
    if (userCache != null) {
      userCache.remove(username);
    }
  }

  /**
   * Clears all entries from the cache.
   */
  public void clearCache() {
    if (userCache != null) {
      userCache.clear();
    }
  }

  /**
   * Checks if caching is available.
   * 
   * @return true if the cache is initialized and available
   */
  public boolean isCacheAvailable() {
    return userCache != null;
  }

  /**
   * Checks if a cache entry has expired.
   */
  private boolean isExpired(CacheEntry entry) {
    return System.currentTimeMillis() - entry.getCreationTime() > CACHE_EXPIRY_MS;
  }

  /**
   * Inner class to store cache entries with creation timestamp.
   */
  private static class CacheEntry {
    private final UserDetails userDetails;
    private final long creationTime;

    public CacheEntry(UserDetails userDetails) {
      this.userDetails = userDetails;
      this.creationTime = System.currentTimeMillis();
    }

    public UserDetails getUserDetails() {
      return userDetails;
    }

    public long getCreationTime() {
      return creationTime;
    }
  }
}