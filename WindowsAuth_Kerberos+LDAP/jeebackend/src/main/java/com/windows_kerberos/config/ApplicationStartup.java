package com.windows_kerberos.config;

import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.inject.Inject;

import com.windows_kerberos.auth.KerberosUtil;

@Singleton
@Startup
public class ApplicationStartup {
  private static final Logger LOGGER = Logger.getLogger(ApplicationStartup.class.getName());

  @Inject
  private KerberosUtil kerberosUtil;

  @PostConstruct
  public void init() {
    LOGGER.info("Initializing application...");

    // Configure Kerberos
    kerberosUtil.configureKerberos();

    LOGGER.info("Application initialization complete");
  }
}