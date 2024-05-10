package com.ibm.security.appscan.altoromutual.servlet;

import java.io.IOException;


import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.ibm.security.appscan.altoromutual.util.OperationsUtil;
import com.ibm.security.appscan.altoromutual.util.ServletUtil;

public class TransferServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        doPost(req, resp);
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        if (!ServletUtil.isLoggedin(request)) {
            response.sendRedirect("login.jsp");
            return;
        }

        // Secure parameter handling
        String accountIdString = request.getParameter("fromAccount");
        long creditActId = Long.parseLong(request.getParameter("toAccount"));
        double amount = Double.valueOf(request.getParameter("transferAmount"));

        // Sanitize inputs
        accountIdString = sanitizeInput(accountIdString);
        // No need to sanitize creditActId as it's converted directly to long
        // No need to sanitize amount as it's converted directly to double

        String message = OperationsUtil.doServletTransfer(request, creditActId, accountIdString, amount);

        RequestDispatcher dispatcher = request.getRequestDispatcher("transfer.jsp");
        request.setAttribute("message", message);
        dispatcher.forward(request, response);
    }

    // Method to sanitize input to prevent potential SQL injection
    private String sanitizeInput(String input) {
        // Check if input is null or empty
        if (input == null || input.isEmpty()) {
            return input;
        }

        // Remove or neutralize potentially harmful characters
        // For example, you can remove all non-alphanumeric characters
        // or allow only specific characters based on your application's requirements

        StringBuilder sanitizedInput = new StringBuilder();
        for (char c : input.toCharArray()) {
            // Allow alphanumeric characters
            if (Character.isLetterOrDigit(c)) {
                sanitizedInput.append(c);
            }
            // Allow specific additional characters if needed
            // Example: Allow space and underscore characters
            else if (c == ' ' || c == '_') {
                sanitizedInput.append(c);
            }
            // Add additional conditions for specific characters to allow
        }

        return sanitizedInput.toString();
    }

}
