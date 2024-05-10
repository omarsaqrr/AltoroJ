package com.ibm.security.appscan.altoromutual.api;

import javax.annotation.security.PermitAll;
import javax.servlet.http.HttpServletRequest;
import javax.websocket.server.PathParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.wink.json4j.JSONException;
import org.apache.wink.json4j.JSONObject;

import com.ibm.security.appscan.altoromutual.model.Feedback;
import com.ibm.security.appscan.altoromutual.util.OperationsUtil;
import com.ibm.security.appscan.altoromutual.util.ServletUtil;

@Path("/feedback")
public class FeedbackAPI extends AltoroAPI {

    private static final int MAX_NAME_LENGTH = 50;
    private static final int MAX_EMAIL_LENGTH = 100;
    private static final int MAX_SUBJECT_LENGTH = 100;
    private static final int MAX_COMMENTS_LENGTH = 1000;
    
    // Track the number of requests made by each client within a time frame
    private static final Map<String, Integer> requestCountMap = new ConcurrentHashMap<>();
    private static final int MAX_REQUESTS_PER_MINUTE = 10; // Maximum requests allowed per minute

    @POST
    @PermitAll
    @Path("/submit")
    public Response sendFeedback(String bodyJSON, @Context HttpServletRequest request) throws JSONException {
        // Check if the client has exceeded the request limit
        String clientIp = request.getRemoteAddr();
        if (exceedsRequestLimit(clientIp)) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"Error\": \"Rate limit exceeded. Please try again later.\"}").build();
        }

        JSONObject myJson;
        try {
            myJson = new JSONObject(bodyJSON);
        } catch (JSONException e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{\"Error\": \"Request is not in JSON format\"}").build();
        }

        // Get the feedback details
        String name;
        String email;
        String subject;
        String comments;

        try {
            name = truncateString(myJson.optString("name"), MAX_NAME_LENGTH);
            email = truncateString(myJson.optString("email"), MAX_EMAIL_LENGTH);
            subject = truncateString(myJson.optString("subject"), MAX_SUBJECT_LENGTH);
            comments = truncateString(myJson.optString("message"), MAX_COMMENTS_LENGTH);
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"Error\": \"" + e.getMessage() + "\"}").build();
        }

        String feedbackId = OperationsUtil.sendFeedback(name, email, subject, comments);

        JSONObject responseJson = new JSONObject();
        if (feedbackId != null) {
            responseJson.put("status", "Thank you!");
            responseJson.put("feedbackId", feedbackId);
            return Response.status(Response.Status.OK)
                    .entity(responseJson.toString()).type(MediaType.APPLICATION_JSON_TYPE).build();
        } else {
            responseJson.put("name", name);
            responseJson.put("email", email);
            responseJson.put("subject", subject);
            responseJson.put("comments", comments);
            return Response.status(Response.Status.OK)
                    .entity(responseJson.toString()).type(MediaType.APPLICATION_JSON_TYPE).build();
        }
    }

    // Truncate the input string if it exceeds the specified length
    private String truncateString(String input, int maxLength) {
        if (input.length() > maxLength) {
            throw new IllegalArgumentException("Input length exceeds maximum allowed length");
        }
        return input;
    }
    
    // Check if the client has exceeded the request limit
    private boolean exceedsRequestLimit(final String clientIp) {
        long currentTime = System.currentTimeMillis();
        int count = requestCountMap.getOrDefault(clientIp, 0);
        if (count >= MAX_REQUESTS_PER_MINUTE) {
            return true;
        }
        requestCountMap.put(clientIp, count + 1);
        // Remove client IP from map after a minute
        new java.util.Timer().schedule(
            new java.util.TimerTask() {
                @Override
                public void run() {
                    requestCountMap.remove(clientIp);
                }
            },
            60 * 1000 // Remove after 1 minute
        );
        return false;
    }
    
    @GET
    @Path("/{feedbackId}")
    public Response getFeedback(@PathParam("feedbackId") String feedbackId, @Context HttpServletRequest request) throws JSONException {
        // Validate feedbackId
        if (!isValidFeedbackId(feedbackId)) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"Error\": \"Invalid feedback ID\"}").build();
        }

        // Retrieve feedback details based on the feedbackId
        Feedback feedbackDetails = ServletUtil.getFeedback(Long.parseLong(feedbackId));
        if (feedbackDetails == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("{\"Error\": \"Feedback not found\"}").build();
        }

        // Construct JSON response
        JSONObject responseJson = new JSONObject();
        responseJson.put("name", feedbackDetails.getName());
        responseJson.put("email", feedbackDetails.getEmail());
        responseJson.put("subject", feedbackDetails.getSubject());
        responseJson.put("message", feedbackDetails.getMessage());

        return Response.status(Response.Status.OK)
                .entity(responseJson.toString())
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    // Validate feedbackId
    private boolean isValidFeedbackId(String feedbackId) {
        // Check if feedbackId is not null and not empty
        if (feedbackId == null || feedbackId.isEmpty()) {
            return false;
        }
        
        // Check if feedbackId consists only of digits (numeric)
        if (!feedbackId.matches("\\d+")) {
            return false;
        }
        
        return true;
    }
}
