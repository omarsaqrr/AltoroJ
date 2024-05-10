package com.ibm.security.appscan.altoromutual.servlet;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.ibm.security.appscan.altoromutual.model.User;

/**
 * This servlet allows the users to view account and transaction information.
 * Servlet implementation class AccountServlet
 * @author Alexei
 *
 */
public class AccountViewServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    /**
     * @see HttpServlet#HttpServlet()
     */
    public AccountViewServlet() {
        super();
    }

    /**
     * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
     */
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Check if the user is authenticated
        if (!isLoggedIn(request)) {
            response.sendRedirect(request.getContextPath() + "/login.jsp"); // Redirect unauthorized users to login page
            return;
        }

        // Show account balance for a particular account
        if (request.getRequestURL().toString().endsWith("showAccount")) {
            String accountName = request.getParameter("listAccounts");
            if (accountName == null) {
                response.sendRedirect(request.getContextPath() + "/bank/main.jsp");
                return;
            }

            // Indirectly reference account-related information using session attribute
            HttpSession session = request.getSession();
            session.setAttribute("accountId", accountName);
            RequestDispatcher dispatcher = request.getRequestDispatcher("/bank/balance.jsp");
            dispatcher.forward(request, response);
            return;
        } else if (request.getRequestURL().toString().endsWith("showTransactions")) {
            doPost(request, response);
        } else {
            super.doGet(request, response);
        }
    }

    /**
     * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
     */
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Check if the user is authenticated
        if (!isLoggedIn(request)) {
            response.sendRedirect(request.getContextPath() + "/login.jsp"); // Redirect unauthorized users to login page
            return;
        }

        // Show transactions within the specified date range (if any)
        if (request.getRequestURL().toString().endsWith("showTransactions")) {
            String startTime = request.getParameter("startDate");
            String endTime = request.getParameter("endDate");

            // Indirectly reference account-related information using session attribute
            HttpSession session = request.getSession();
            session.setAttribute("startTime", startTime);
            session.setAttribute("endTime", endTime);

            RequestDispatcher dispatcher = request.getRequestDispatcher("/bank/transaction.jsp");
            dispatcher.forward(request, response);
        }
    }

    /**
     * Check if the user is authenticated
     */
    private boolean isLoggedIn(HttpServletRequest request) {
        // Check if a session exists
        HttpSession session = request.getSession(false);
        if (session != null) {
            // Check if the "user" attribute exists in the session
            Object userAttribute = session.getAttribute("user");
            if (userAttribute != null && userAttribute instanceof User) {
                // Optionally, you may perform additional checks such as session expiration, IP validation, etc.
                return true; // User is authenticated
            }
        }
        return false; // User is not authenticated
    }

}
