package com.example;

import jakarta.enterprise.context.RequestScoped;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/api")
@RequestScoped
public class SecuredResource {

  @GET
  @Path("/public")
  @Produces(MediaType.APPLICATION_JSON)
  public Response publicEndpoint() {
    return Response.ok("{\"message\": \"This is a public endpoint\"}")
        .header("Access-Control-Allow-Origin", "*")
        .build();
  }

  @GET
  @Path("/secured")
  @Produces(MediaType.APPLICATION_JSON)
  public Response securedEndpoint() {
    return Response.ok("{\"message\": \"This is a secured endpoint\", \"user\": \"test\"}")
        .header("Access-Control-Allow-Origin", "*")
        .build();
  }

  @GET
  @Path("/admin")
  @Produces(MediaType.APPLICATION_JSON)
  public Response adminEndpoint() {
    return Response.ok("{\"message\": \"This is an admin endpoint\", \"user\": \"test\"}")
        .header("Access-Control-Allow-Origin", "*")
        .build();
  }
}
