package com.example;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.ApplicationPath;
import jakarta.ws.rs.core.Application;

@ApplicationPath("/")
@ApplicationScoped
public class JaxRsApplication extends Application {
  // The resources will be automatically discovered
}
