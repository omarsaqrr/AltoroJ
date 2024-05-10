package com.ibm.security.appscan.altoromutual.api;

import javax.annotation.security.PermitAll;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.ibm.security.appscan.altoromutual.util.ServletUtil;

@Path("/logout")
public class LogoutAPI extends AltoroAPI {

    @GET
    @PermitAll
    public Response doLogOut(@Context HttpServletRequest request) {

        try {
            request.getSession().removeAttribute(ServletUtil.SESSION_ATTR_USER);
            String response = "{\"LoggedOut\" : \"True\"}";
            // Enforce HTTPS for the response
            return Response.status(Response.Status.OK)
                           .entity(response)
                           .type(MediaType.APPLICATION_JSON_TYPE)
                           .header("Strict-Transport-Security", "max-age=31536000; includeSubDomains") // Enforce HTTPS for subsequent requests
                           .header("Content-Security-Policy", "default-src 'self'") // Content Security Policy to restrict content sources
                           .header("X-Content-Type-Options", "nosniff") // Prevent MIME-sniffing attacks
                           .header("X-Frame-Options", "DENY") // Prevent clickjacking attacks
                           .header("X-XSS-Protection", "1; mode=block") // Enable XSS protection
                           .build();
        } catch (Exception e) {
            String response = "{\"Error \": \"Unknown error encountered\"}";
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(response).build();
        }
    }
}
