package com.ibm.security.appscan.altoromutual.api;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.wink.json4j.*;

import com.ibm.security.appscan.altoromutual.util.OperationsUtil;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import com.ibm.security.appscan.altoromutual.util.DBUtil;

@Path("transfer")
public class TransferAPI extends AltoroAPI {
    
    @POST
    public Response transfer(String bodyJSON,
            @Context HttpServletRequest request) {
        
        JSONObject myJson = new JSONObject();
        Long creditActId;
        Long fromAccount;
        double amount;
        String message;
        
        try {
            myJson = new JSONObject(bodyJSON);
            // Get the transaction parameters
            creditActId = Long.parseLong(myJson.get("toAccount").toString());
            fromAccount = Long.parseLong(myJson.get("fromAccount").toString());
            amount = Double.parseDouble(myJson.get("transferAmount").toString());

            // Use prepared statement to execute parameterized query
            String sqlQuery = "INSERT INTO transfers (to_account, from_account, amount) VALUES (?, ?, ?)";
            try (PreparedStatement statement = DBUtil.getConnection().prepareStatement(sqlQuery)) {
                statement.setLong(1, creditActId);
                statement.setLong(2, fromAccount);
                statement.setDouble(3, amount);
                statement.executeUpdate();
            } catch (SQLException e) {
                // Handle SQL exception
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                        .entity("An error has occurred while processing the transfer: " + e.getMessage())
                        .build();
            }

            message = OperationsUtil.doApiTransfer(request, creditActId, fromAccount, amount);
        } catch (JSONException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("An error has occurred: " + e.getLocalizedMessage())
                    .build();
        }
            
        if (message.startsWith("ERROR")) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("\"error\":\"" + message + "\"}")
                    .build();
        }
        
        return Response.status(Response.Status.OK)
                .entity("{\"success\":\"" + message + "\"}")
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }
}
