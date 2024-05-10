package com.ibm.security.appscan.altoromutual.api;

import java.io.IOException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.wink.json4j.JSONException;
import org.apache.wink.json4j.JSONObject;

import com.ibm.security.appscan.altoromutual.util.DBUtil;
import com.ibm.security.appscan.altoromutual.util.ServletUtil;

@Path("/admin")
public class AdminAPI extends AltoroAPI {
    
    @POST
    @Path("/changePassword")
    public Response changePassword(String bodyJSON, @Context HttpServletRequest request) throws IOException {
        // Check if the user is authorized to perform this action
        if (!isUserAuthorized(request, "admin")) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("{\"error\":\"You are not authorized to perform this action.\"}").build();
        }
        
        JSONObject bodyJson = new JSONObject();
        String username;
        String password1;
        String password2;
        
        try {
            bodyJson = new JSONObject(bodyJSON);
            // Parse the body for the required parameters
            username = bodyJson.optString("username");
            password1 = bodyJson.optString("password1");
            password2 = bodyJson.optString("password2");
        } catch (JSONException e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{\"Error\": \"Request is not in JSON format\"}").build();
        }
        
        // Try to change the password
        if (username == null || username.trim().isEmpty()
                || password1 == null || password1.trim().isEmpty()
                || password2 == null || password2.trim().isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\":\"An error has occurred. Please try again later.\"}").build();
        }
        
        if (!password1.equals(password2)) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\":\"Entered passwords did not match.\"}").build();
        }
        
        String error = null;
        
        if (ServletUtil.getAppProperty("enableAdminFunctions").equalsIgnoreCase("true")) {
            try {
                // Use parameterized query to prevent SQL injection
                String query = "UPDATE users SET password = ? WHERE username = ?";
                PreparedStatement statement = DBUtil.getConnection().prepareStatement(query);
                statement.setString(1, password1);
                statement.setString(2, username);
                statement.executeUpdate();
            } catch (SQLException e) {
                error = e.getMessage();
            }
        }
        
        if (error != null) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{\"error\":\"" + error + "\"}").build();
        }
        
        return Response.status(Response.Status.OK)
                .entity("{\"success\":\"Requested operation has completed successfully.\"}")
                .type(MediaType.APPLICATION_JSON_TYPE).build();
    }
    
    @POST
    @Path("/addUser")
    public Response addUser(String bodyJSON, @Context HttpServletRequest request) throws IOException {
        // Check if the user is authorized to perform this action
        if (!isUserAuthorized(request, "admin")) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("{\"error\":\"You are not authorized to perform this action.\"}").build();
        }
        
        JSONObject bodyJson = new JSONObject();
        String firstname;
        String lastname;
        String username;
        String password1;
        String password2;
        
        try {
            bodyJson = new JSONObject(bodyJSON);
            // Parse the request for the required parameters
            firstname = bodyJson.optString("firstname");
            lastname = bodyJson.optString("lastname");
            username = bodyJson.optString("username");
            password1 = bodyJson.optString("password1");
            password2 = bodyJson.optString("password2");
        } catch (JSONException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"Error\": \"Request is not in JSON format\"}").build();
        }
        
        if (username == null || username.trim().isEmpty()
                || password1 == null || password1.trim().isEmpty()
                || password2 == null || password2.trim().isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\":\"An error has occurred. Please try again later.\"}").build();
        }
        
        if (!password1.equals(password2)) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\":\"Entered passwords did not match.\"}").build();
        }
        
        String error = null;
        
        if (ServletUtil.getAppProperty("enableAdminFunctions").equalsIgnoreCase("true")) {
            try {
                // Use parameterized query to prevent SQL injection
                String query = "INSERT INTO users (username, password, firstname, lastname) VALUES (?, ?, ?, ?)";
                PreparedStatement statement = DBUtil.getConnection().prepareStatement(query);
                statement.setString(1, username);
                statement.setString(2, password1);
                statement.setString(3, firstname);
                statement.setString(4, lastname);
                statement.executeUpdate();
            } catch (SQLException e) {
                error = e.getMessage();
            }
        }
        
        if (error != null) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{\"error\":\"" + error + "\"}").build();
        }
        
        return Response.status(Response.Status.OK)
                .entity("{\"success\":\"Requested operation has completed successfully.\"}")
                .type(MediaType.APPLICATION_JSON_TYPE).build();
    }
    
    // Method to check if the user is authorized to perform administrative actions
    private boolean isUserAuthorized(HttpServletRequest request, String requiredRole) {
        // Check if the user is authenticated
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("username") == null) {
            return false;
        }
        
        // Check if the user has the required role
        String username = (String) session.getAttribute("username");
        String userRole = getUserRole(username);
        
        return requiredRole.equals(userRole);
    }
    
    // Method to retrieve the role of the user from the database
    private String getUserRole(String username) {
        try {
            // Assuming you have a table 'user_roles' with columns 'username' and 'role'
            String query = "SELECT role FROM user_roles WHERE username = ?";
            PreparedStatement statement = DBUtil.getConnection().prepareStatement(query);
            statement.setString(1, username);
            ResultSet rs = statement.executeQuery();
            if (rs.next()) {
                return rs.getString("role");
            }
        } catch (SQLException e) {
            // Handle SQLException
            e.printStackTrace();
        }
        return null; // Return null if role not found
    }
}
