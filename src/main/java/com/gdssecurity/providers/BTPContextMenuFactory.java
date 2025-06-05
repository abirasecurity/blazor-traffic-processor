package com.gdssecurity.providers;
import com.gdssecurity.helpers.ActiveCircuitTracker;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpHeader;

import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import java.awt.Component;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;


/**
 * Context menu factory for BTP frames.
 */
public class BTPContextMenuFactory implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private static final Logger logger = Logger.getLogger("BTP");

    public BTPContextMenuFactory(MontoyaApi api) {
        this.api = api;
        logger.info("[BTPContextMenuFactory] Constructor called. Thread: " + Thread.currentThread().getName());
    }


    /**
     * Sends both the original and circuit-updated request to Repeater.
     * @param api MontoyaApi instance
     * @param reqResp HttpRequestResponse to clone and update
     * @param parentComponent Parent UI component for dialogs
     */
    private void sendOriginalAndUpdatedToRepeater(MontoyaApi api, HttpRequestResponse reqResp, Component parentComponent) {
        try {
            logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPContextMenuFactory] sendOriginalAndUpdatedToRepeater() called. URL: %3$s",
                    System.currentTimeMillis(), Thread.currentThread().getName(),
                    (reqResp != null && reqResp.request() != null ? reqResp.request().url() : "null")));

            if (reqResp == null || reqResp.request() == null) {
                logger.warning("[BTPContextMenuFactory] No request to send to Repeater.");
                JOptionPane.showMessageDialog(parentComponent, "No request available to send to Repeater.");
                return;
            }

            // Send original request
            api.repeater().sendToRepeater(reqResp.request());
            logger.info("[BTPContextMenuFactory] Sent original request to Repeater: " + reqResp.request().url());

            // Get the latest active circuit token
            String latestToken = ActiveCircuitTracker.getLatestToken();
            if (latestToken == null) {
                logger.warning("[BTPContextMenuFactory] No active circuit token found. Only original request sent.");
                JOptionPane.showMessageDialog(parentComponent, "No active circuit token found. Only original request sent to Repeater.");
                return;
            }

            // Clone and update the URL's id parameter
            String url = reqResp.request().url();
            if (!url.contains("id=")) {
                logger.warning("[BTPContextMenuFactory] No id parameter in URL. Only original request sent.");
                JOptionPane.showMessageDialog(parentComponent, "No id parameter in URL. Only original request sent to Repeater.");
                return;
            }
            String updatedUrl = url.replaceAll("id=[^&]+", "id=" + latestToken);

            // Build the request line
            String method = reqResp.request().method();
            String httpVersion = "HTTP/1.1";
            int pathStart = updatedUrl.indexOf("/", updatedUrl.indexOf("://") + 3);
            String pathAndQuery = pathStart != -1 ? updatedUrl.substring(pathStart) : updatedUrl;

            StringBuilder rawRequest = new StringBuilder();
            rawRequest.append(method).append(" ").append(pathAndQuery).append(" ").append(httpVersion).append("\r\n");

            // Copy headers except pseudo-headers
            List<HttpHeader> headers = reqResp.request().headers();
            for (HttpHeader header : headers) {
                String name = header.name();
                if (!name.equalsIgnoreCase(":method") && !name.equalsIgnoreCase(":path")) {
                    rawRequest.append(name).append(": ").append(header.value()).append("\r\n");
                }
            }
            rawRequest.append("\r\n");

            // Use the current request body (as byte array)
            ByteArray body = reqResp.request().body();
            if (body != null && body.length() > 0) {
                rawRequest.append(body.toString());
            }

            // Create the updated HttpRequest from raw bytes
            HttpRequest updatedRequest = HttpRequest.httpRequest(ByteArray.byteArray(rawRequest.toString().getBytes()));
            api.repeater().sendToRepeater(updatedRequest);
            logger.info("[BTPContextMenuFactory] Sent updated request to Repeater: " + updatedUrl);

            JOptionPane.showMessageDialog(parentComponent,
                    "Both original and circuit-updated requests sent to Repeater.",
                    "Send to Repeater",
                    JOptionPane.INFORMATION_MESSAGE);

        } catch (Exception ex) {
            logger.log(Level.SEVERE, "[BTPContextMenuFactory] Error sending requests to Repeater", ex);
            JOptionPane.showMessageDialog(parentComponent, "Failed to send to Repeater: " + ex.getMessage());
        }
    }
    /**
     * Provides context menu items for BTP frames.
     * @param event The context menu event from Burp.
     * @return List of JMenuItem as Component.
     */
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        logger.info("[BTPContextMenuFactory] provideMenuItems() called. Thread: " + Thread.currentThread().getName());

        Optional<HttpRequestResponse> maybeReqResp = event.messageEditorRequestResponse().map(m -> m.requestResponse());
        if (maybeReqResp.isEmpty()) {
            logger.info("[BTPContextMenuFactory] No HttpRequestResponse found for context menu.");
            return List.of();
        }
        HttpRequestResponse reqResp = maybeReqResp.get();

        List<Component> menuItems = new ArrayList<>();

        JMenuItem sendToIntruder = new JMenuItem("Send to Intruder");
        sendToIntruder.addActionListener(e -> {
            try {
                api.intruder().sendToIntruder(reqResp.request());
                logger.info("[BTPContextMenuFactory] Sent to Intruder: " + reqResp.url());
            } catch (Exception ex) {
                logger.log(Level.SEVERE, "[BTPContextMenuFactory] Error sending to Intruder", ex);
                JOptionPane.showMessageDialog(null, "Failed to send to Intruder: " + ex.getMessage());
            }
        });
        menuItems.add(sendToIntruder);


        JMenuItem sendToRepeater_update_circuit = new JMenuItem("Send to Repeater (and update circuit)");
        sendToRepeater_update_circuit.addActionListener(e -> {
            sendOriginalAndUpdatedToRepeater(api, reqResp, null); // or pass your main UI component if you want dialogs parented
        });
        menuItems.add(sendToRepeater_update_circuit);

        JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
        sendToRepeater.addActionListener(e -> {
            try {
                api.repeater().sendToRepeater(reqResp.request());
                logger.info("[BTPContextMenuFactory] Sent to Repeater: " + reqResp.url());
            } catch (Exception ex) {
                logger.log(Level.SEVERE, "[BTPContextMenuFactory] Error sending to Repeater", ex);
                JOptionPane.showMessageDialog(null, "Failed to send to Repeater: " + ex.getMessage());
            }
        });
        menuItems.add(sendToRepeater);

        JMenuItem copy = new JMenuItem("Copy");
        copy.addActionListener(e -> {
            try {
                ByteArray body = reqResp.response() != null ? reqResp.response().body() : null;
                StringSelection selection = new StringSelection(body == null ? "" : body.toString());
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
                logger.info("[BTPContextMenuFactory] Copied response body to clipboard.");
            } catch (Exception ex) {
                logger.log(Level.SEVERE, "[BTPContextMenuFactory] Error copying to clipboard", ex);
                JOptionPane.showMessageDialog(null, "Failed to copy: " + ex.getMessage());
            }
        });
        menuItems.add(copy);

        return menuItems;
    }
}
