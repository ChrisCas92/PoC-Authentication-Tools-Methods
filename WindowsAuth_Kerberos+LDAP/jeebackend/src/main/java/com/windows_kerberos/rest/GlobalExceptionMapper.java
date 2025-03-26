package com.windows_kerberos.rest;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

@Provider
public class GlobalExceptionMapper implements ExceptionMapper<Exception> {
  private static final Logger LOGGER = Logger.getLogger(GlobalExceptionMapper.class.getName());

  @Override
  public Response toResponse(Exception exception) {
    LOGGER.log(Level.SEVERE, "Unhandled exception", exception);

    Map<String, Object> error = new HashMap<>();
    error.put("error", true);
    error.put("message", exception.getMessage());

    // Determine the appropriate status code
    int statusCode = Response.Status.INTERNAL_SERVER_ERROR.getStatusCode();
    if (exception instanceof SecurityException) {
      statusCode = Response.Status.UNAUTHORIZED.getStatusCode();
    }

    return Response
        .status(statusCode)
        .entity(error)
        .build();
  }
}