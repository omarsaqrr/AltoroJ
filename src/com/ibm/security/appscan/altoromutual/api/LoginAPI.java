package com.ibm.security.appscan.altoromutual.api;

import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.security.PermitAll;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.apache.commons.codec.binary.Base64;
import org.apache.wink.json4j.*;
import com.ibm.security.appscan.altoromutual.util.DBUtil;

@Path("/login")
public class LoginAPI {

    private static final int MAX_LOGIN_ATTEMPTS = 5;
    private static final long LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes in milliseconds
    private static Map<String, LoginAttempt> loginAttempts = new HashMap<>();

    @GET
    public Response checkLogin(@Context HttpServletRequest request) throws JSONException {
        JSONObject myJson = new JSONObject();
        myJson.put("loggedin", "true");
        return Response.status(Response.Status.OK).entity(myJson.toString()).type(MediaType.APPLICATION_JSON_TYPE).build();
    }

    @POST
    @PermitAll
    public Response login(String bodyJSON, @Context HttpServletRequest request) throws JSONException {

        JSONObject myJson = new JSONObject();
        try {
            myJson = new JSONObject(bodyJSON);
        } catch (Exception e) {
            myJson.clear();
            myJson.put("error", "body is not JSON");
            return Response.status(Response.Status.BAD_REQUEST).entity(myJson.toString()).build();
        }

        String username = myJson.optString("username");
        String password = myJson.optString("password");
        if (username == null || username.isEmpty() || password == null || password.isEmpty()) {
            myJson.clear();
            myJson.put("error", "Invalid username or password");
            return Response.status(Response.Status.BAD_REQUEST).entity(myJson.toString()).build();
        }

        username = username.toLowerCase();
        password = password.toLowerCase();

        myJson.clear();

        // Check if the user is currently locked out due to too many failed attempts
        LoginAttempt attempt = loginAttempts.get(username);
        if (attempt != null && attempt.isLockedOut()) {
            long remainingTime = attempt.getLockoutTime() + LOCKOUT_DURATION - System.currentTimeMillis();
            myJson.put("error", "Account locked. Please try again after " + remainingTime / 1000 + " seconds.");
            return Response.status(Response.Status.BAD_REQUEST).entity(myJson.toString()).build();
        }

        try {
            if (!DBUtil.isValidUser(username, password)) {
                // Increment the failed login attempt count
                if (attempt == null) {
                    attempt = new LoginAttempt();
                    loginAttempts.put(username, attempt);
                }
                attempt.incrementAttempts();

                // Lock the account if the maximum number of attempts is reached
                if (attempt.getAttempts() >= MAX_LOGIN_ATTEMPTS) {
                    attempt.setLockedOut(true);
                    attempt.setLockoutTime(System.currentTimeMillis());
                }

                throw new InvalidParameterException("Invalid username or password.");
            }
        } catch (Exception e) {
            if (e instanceof InvalidParameterException)
                System.out.println("Invalid user error: " + e.getLocalizedMessage());

            myJson.put("error", e.getLocalizedMessage());
            return Response.status(Response.Status.BAD_REQUEST).entity(myJson.toString()).build();
        }

        // Successful login
        try {
            myJson.put("success", username + " is now logged in");

            SecureRandom secureRandom = new SecureRandom();
            byte[] randomBytes = new byte[32];
            secureRandom.nextBytes(randomBytes);
            String authToken = Base64.encodeBase64String(randomBytes);

            myJson.put("Authorization", authToken);
            return Response.status(Response.Status.OK).entity(myJson.toString()).type(MediaType.APPLICATION_JSON_TYPE).build();
        } catch (Exception ex) {
            myJson.put("failed", "Unexpected error occurred. Please try again.");
            myJson.put("error", ex.getLocalizedMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(myJson.toString()).build();
        }
    }

    private static class LoginAttempt {
        private int attempts;
        private boolean lockedOut;
        private long lockoutTime;

        public LoginAttempt() {
            this.attempts = 0;
            this.lockedOut = false;
            this.lockoutTime = 0;
        }

        public int getAttempts() {
            return attempts;
        }

        public void incrementAttempts() {
            attempts++;
        }

        public boolean isLockedOut() {
            return lockedOut;
        }

        public void setLockedOut(boolean lockedOut) {
            this.lockedOut = lockedOut;
        }

        public long getLockoutTime() {
            return lockoutTime;
        }

        public void setLockoutTime(long lockoutTime) {
            this.lockoutTime = lockoutTime;
        }
    }
}
