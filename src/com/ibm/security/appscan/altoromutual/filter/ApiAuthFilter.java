package com.ibm.security.appscan.altoromutual.filter;

import java.io.IOException;
import java.security.Key;
import java.util.List;

import javax.annotation.security.PermitAll;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

public class ApiAuthFilter implements ContainerRequestFilter {

    @Context
    private ResourceInfo resourceInfo;

    private static final String NOT_LOGGED_IN_ERROR = "loggedIn=false" + System.lineSeparator() + "Please log in first";

    // Secret key for token encryption/decryption (must be kept secure)
    private static final String SECRET_KEY = "YourSecretKey";

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {

        java.lang.reflect.Method method = resourceInfo.getResourceMethod();

        if (method.isAnnotationPresent(PermitAll.class)) {
            return;
        }

        // Ensure the request is over HTTPS
        if (!requestContext.getSecurityContext().isSecure()) {
            requestContext.abortWith(Response.status(Response.Status.FORBIDDEN)
                    .entity("HTTPS is required for this endpoint").build());
            return;
        }

        // Get request headers
        final MultivaluedMap<String, String> headers = requestContext.getHeaders();
        final List<String> authorization = headers.get("Authorization");

        // If there's no authorization present, deny request
        if (authorization == null || authorization.isEmpty()) {
            requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED)
                    .entity(NOT_LOGGED_IN_ERROR).build());
            return;
        }

        // Get the token from the authorization header
        String token = authorization.get(0);

        // Decrypt and validate the token
        if (!isValidToken(token)) {
            requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED)
                    .entity(NOT_LOGGED_IN_ERROR).build());
            return;
        }
    }

    // Method to validate the token (dummy implementation)
    private boolean isValidToken(String token) {
        try {
            // Decrypt the token using the secret key
            Cipher cipher = Cipher.getInstance("AES");
            Key secretKey = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedBytes = cipher.doFinal(token.getBytes());

            // Perform validation checks on the decrypted token
            // For demonstration purposes, assume all tokens are valid
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
