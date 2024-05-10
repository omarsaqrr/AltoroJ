package com.ibm.security.appscan.altoromutual.api;

import java.sql.SQLException;
import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.wink.json4j.JSONException;
import org.apache.wink.json4j.JSONObject;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import com.ibm.security.appscan.altoromutual.model.Account;
import com.ibm.security.appscan.altoromutual.model.Transaction;
import com.ibm.security.appscan.altoromutual.model.User;
import com.ibm.security.appscan.altoromutual.util.DBUtil;
import com.ibm.security.appscan.altoromutual.util.OperationsUtil;

@Path("/account")
public class AccountAPI extends AltoroAPI {

    // For the get method return all accounts
    @GET
    public Response getAccounts(@Context HttpServletRequest request) {
        if (!isLoggedIn(request)) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Error: Unauthorized access").build();
        }
        
        String response;
        try {
            Account[] account = OperationsUtil.getUser(request).getAccounts();
            response = "{\"Accounts\":\n[\n";
            for (int i = 0; i < account.length; i++) {
                response = response + "{ \"Name\" : \"" + account[i].getAccountName()
                        + "\", \"id\": \"" + account[i].getAccountId() + "\"}";
                if (i < account.length - 1)
                    response = response + ",\n";
            }
            response = response + "\n]}";
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Error: " + e.getLocalizedMessage()).build();
        }
        return Response.status(Response.Status.OK).entity(response).type(MediaType.APPLICATION_JSON_TYPE).build();
    }

    // Method to return details about a specific account
    @GET
    @Path("/{accountNo}")
    public Response getAccountDetails(@PathParam("accountNo") String accountNo,
            @Context HttpServletRequest request) {
        if (!isLoggedIn(request)) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Error: Unauthorized access").build();
        }
        
        String response;
        try {
            // Get the account balance using parameterized query
            double dblBalance = Account.getAccountBalance(accountNo);
            String format = (dblBalance < 1) ? "$0.00" : "$.00";
            String balance = new DecimalFormat(format).format(dblBalance);
            response = "{\"balance\" : \"" + balance + "\" ,\n";
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{Error : " + e.getLocalizedMessage())
                    .build();
        }
        // Get the last 10 transactions
        String last10Transactions;
        last10Transactions = this.getLastTenTransactions(accountNo);
        if (last10Transactions.equals("Error")) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{Error : Unexpected error during transfer}")
                    .build();
        }
        response = response + last10Transactions;

        return Response.status(Response.Status.OK).entity(response).type(MediaType.APPLICATION_JSON_TYPE).build();
    }

    // Methods for getting the transactions

    // Get the last 10 transactions
    @GET
    @Path("/{accountNo}/transactions")
    public Response showLastTenTransactions(
            @PathParam("accountNo") String accountNo,
            @Context HttpServletRequest request) {
        if (!isLoggedIn(request)) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Error: Unauthorized access").build();
        }
        
        String response;
        response = "{";
        // Get the last 10 transactions
        String last10Transactions;
        last10Transactions = this.getLastTenTransactions(accountNo);
        if (last10Transactions.equals("Error")) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{Error : Unexpected error during transfer}")
                    .build();
        }
        response = response + last10Transactions;
        response = response + "}";

        return Response.status(Response.Status.OK).entity(response).type(MediaType.APPLICATION_JSON_TYPE).build();
    }

    // Get transactions between two dates
    @POST
    @Path("/{accountNo}/transactions")
    public Response getTransactions(@PathParam("accountNo") String accountNo,
            String bodyJSON, @Context HttpServletRequest request) throws SQLException {
        if (!isLoggedIn(request)) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Error: Unauthorized access").build();
        }
        
        User user = OperationsUtil.getUser(request);
        String startString;
        String endString;
        try {
            JSONObject myJson = new JSONObject(bodyJSON);
            startString = (String) myJson.get("startDate");
            endString = (String) myJson.get("endDate");
        } catch (JSONException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{Error : Unexpected request format}")
                    .build();
        }
        Transaction[] transactions = new Transaction[0];
        try {
            Account[] account = new Account[1];
            account[0] = user.lookupAccount(Long.parseLong(accountNo));
            transactions = user.getUserTransactions(startString, endString,
                    account);
        } catch (SQLException e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{Error : Database failed to return requested data} " + e.getLocalizedMessage())
                    .build();
        }

        String response = "{\"transactions\":[";
        for (int i = 0; i < transactions.length; i++) {
            // limit to 100 entries
            if (i == 100)
                break;
            double dblAmt = transactions[i].getAmount();
            String format = (dblAmt < 1) ? "$0.00" : "$.00";
            String amount = new DecimalFormat(format).format(dblAmt);
            String date = new SimpleDateFormat("yyyy-MM-dd HH:mm")
                    .format(transactions[i].getDate());

            response += "{\"id\":" + "\"" + transactions[i].getTransactionId()
                    + "\"," + "\"date\":" + "\"" + date + "\","
                    + "\"account\":\"" + transactions[i].getAccountId() + "\","
                    + "\"type\":\"" + transactions[i].getTransactionType()+
                    "\"," + "\"amount\":\"" + amount + "\"}";
            if(i<transactions.length-1) response+=",";
        }
        response += "]}";
        return Response.status(Response.Status.OK).entity(response).type(MediaType.APPLICATION_JSON_TYPE).build();
    }

    // utilities for the API
    private String getLastTenTransactions(String accountNo) {
        String response = "";
        try {
            response = response + "\"last_10_transactions\" :\n[";
            Transaction[] transactions = DBUtil
                    .getTransactions(null, null, new Account[] { DBUtil
                            .getAccount(Long.valueOf(accountNo)) }, 10);
            for (Transaction transaction : transactions) {
                double dblAmt = transaction.getAmount();
                String dollarFormat = (dblAmt < 1) ? "$0.00" : "$.00";
                String amount = new DecimalFormat(dollarFormat).format(dblAmt);
                String date = new SimpleDateFormat("yyyy-MM-dd")
                        .format(transaction.getDate());
                response = response + "{\"date\" : \"" + date
                        + "\", \"transaction_type\" : \""
                        + transaction.getTransactionType()
                        + "\", \"amount\" : \"" + amount + "\" },\n";
            }
            response = response + "],\n";
        } catch (Exception e) {
            return "Error: " + e.getLocalizedMessage();
        }
        return response;
    }
    
    // Check if user is logged in
    private boolean isLoggedIn(HttpServletRequest request) {
        // Check if a session attribute exists to indicate that the user is logged in
        HttpSession session = request.getSession(false); 
        if (session != null && session.getAttribute("user") != null) {
            return true; 
        }

        // check for a token in the request headers
        String authToken = request.getHeader("Authorization");
        if (authToken != null && authToken.startsWith("Bearer ")) {
            // Extract and validate the token, then check if it belongs to a valid user
            if (isValidToken(authToken.substring(7))) {
                return true; 
            }
        }

        return false;
    }

    private boolean isValidToken(String token) {
        // Implement token validation logic here
        // This could involve decoding the token, checking its expiration, and verifying its signature
        // Return true if the token is valid, false otherwise
        return false; // Placeholder, replace with actual token validation logic
    }

}
