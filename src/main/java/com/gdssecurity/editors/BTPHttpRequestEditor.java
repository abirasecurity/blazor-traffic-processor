package com.gdssecurity.editors;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import com.gdssecurity.MessageModel.GenericMessage;
import com.gdssecurity.helpers.ArraySliceHelper;
import com.gdssecurity.helpers.BTPConstants;
import com.gdssecurity.helpers.BlazorHelper;
import com.gdssecurity.helpers.ActiveCircuitTracker;
import org.json.JSONArray;
import org.json.JSONException;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import javax.swing.Timer;

/**
 * Class to implement the "BTP" editor tab for HTTP requests
 */
public class BTPHttpRequestEditor implements ExtensionProvidedHttpRequestEditor {

    private final MontoyaApi montoya;
    private HttpRequestResponse reqResp;
    private final RawEditor editor;
    private final BlazorHelper blazorHelper;
    private final Logging logging;
    private static final Logger logger = Logger.getLogger("BTP");

    // UI additions
    private JPanel mainPanel;
    private JLabel circuitStatusLabel;
    private JButton updateCircuitButton;

    static {
        try {
            FileHandler fh = new FileHandler("btp-extension.log", true);
            fh.setFormatter(new SimpleFormatter());
            logger.addHandler(fh);
            logger.setLevel(Level.ALL);
        } catch (Exception e) {
            Logger.getAnonymousLogger().log(Level.WARNING, "Failed to set up file handler for BTP logger", e);
        }
    }

    /**
     * Constructs a new BTPHttpRequestEditor object.
     * @param api An instance of the Montoya API.
     * @param editorMode Options for the editor object.
     */
    public BTPHttpRequestEditor(MontoyaApi api, EditorMode editorMode) {
        this.montoya = api;
        this.editor = this.montoya.userInterface().createRawEditor();
        this.blazorHelper = new BlazorHelper(this.montoya);
        this.logging = this.montoya.logging();
        logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditor] Constructor called.",
                System.currentTimeMillis(), Thread.currentThread().getName()));

        // --- UI additions ---
        mainPanel = new JPanel(new BorderLayout());
        circuitStatusLabel = new JLabel();
        updateCircuitButton = new JButton("Update to Active Circuit");

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topPanel.add(circuitStatusLabel);
        topPanel.add(updateCircuitButton);

        mainPanel.add(topPanel, BorderLayout.NORTH);
        mainPanel.add(this.editor.uiComponent(), BorderLayout.CENTER);

        updateCircuitButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    updateRequestUrlWithActiveCircuit();

                    try {
                        // 1. Get the latest editor contents
                        String editorContents = new String(editor.getContents().getBytes(), java.nio.charset.StandardCharsets.ISO_8859_1);
                        byte[] editorBytes = editorContents.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);

                        // 2. Parse the request (headers + request line)
                        burp.api.montoya.http.message.requests.HttpRequest updatedRequest =
                                burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                                        burp.api.montoya.core.ByteArray.byteArray(editorBytes)
                                );

                        // 3. Find the body offset
                        int bodyOffset = blazorHelper.getBodyOffset(editorBytes);
                        if (bodyOffset < 0 || bodyOffset >= editorBytes.length) {
                            logger.warning("[BTPHttpRequestEditor] Could not determine body offset; sending as-is.");
                            sendToRepeaterWithTarget(updatedRequest, null);
                            JOptionPane.showMessageDialog(mainPanel, "Updated request sent to Repeater (body unchanged). Please use the new tab.");
                            return;
                        }

                        // 4. Extract and reserialize the body as BlazorPack
                        byte[] jsonBody = com.gdssecurity.helpers.ArraySliceHelper.getArraySlice(editorBytes, bodyOffset, editorBytes.length);
                        byte[] newBody;
                        try {
                            org.json.JSONArray messages = new org.json.JSONArray(new String(jsonBody, java.nio.charset.StandardCharsets.UTF_8));
                            newBody = blazorHelper.blazorPack(messages);
                        } catch (Exception ex) {
                            logger.log(java.util.logging.Level.WARNING, "[BTPHttpRequestEditor] Body not valid JSON, sending as-is: " + ex.getMessage(), ex);
                            sendToRepeaterWithTarget(updatedRequest, null);
                            JOptionPane.showMessageDialog(mainPanel, "Updated request sent to Repeater (body unchanged). Please use the new tab.");
                            return;
                        }

                        // 5. Build the final request with the reserialized body
                        burp.api.montoya.http.message.requests.HttpRequest finalRequest = updatedRequest.withBody(
                                burp.api.montoya.core.ByteArray.byteArray(newBody)
                        );

                        // 6. Send to Repeater with explicit target
                        sendToRepeaterWithTarget(finalRequest, finalRequest);

                    } catch (Exception ex) {
                        logger.log(java.util.logging.Level.SEVERE, "[BTPHttpRequestEditor] Failed to send updated request to Repeater: " + ex.getMessage(), ex);
                        JOptionPane.showMessageDialog(mainPanel, "Failed to send updated request to Repeater: " + ex.getMessage());
                    }

                } catch (Exception ex) {
                    logger.log(java.util.logging.Level.SEVERE, "[BTPHttpRequestEditor] Error updating to active circuit", ex);
                    JOptionPane.showMessageDialog(mainPanel, "Failed to update circuit: " + ex.getMessage());
                }
            }
        });

        // Add periodic status check
        Timer circuitStatusTimer = new Timer(1000, evt -> updateCircuitStatusLabel());
        circuitStatusTimer.setRepeats(true);
        circuitStatusTimer.start();
    }

    /**
     * Sends the provided request to Repeater, using the Host header as the target if available.
     * If requestForTarget is null, uses the original request for target extraction.
     */
    /**
     * Sends the provided request to Repeater, using the Host header as the target if available.
     * If requestForTarget is null, uses the original request for target extraction.
     */
    /**
     * Sends the provided request to Repeater, using the Host header as the target if available.
     * If requestForTarget is null, uses the original request for target extraction.
     */
    private void sendToRepeaterWithTarget(
            burp.api.montoya.http.message.requests.HttpRequest request,
            burp.api.montoya.http.message.requests.HttpRequest requestForTarget
    ) {
        try {
            burp.api.montoya.http.message.requests.HttpRequest req = requestForTarget != null ? requestForTarget : request;
            String host = null;
            String protocol = "https";
            int port = 443;

            for (burp.api.montoya.http.message.HttpHeader header : req.headers()) {
                if ("Host".equalsIgnoreCase(header.name())) {
                    host = header.value();
                    break;
                }
            }

            if (host != null && host.contains(":")) {
                String[] parts = host.split(":", 2);
                host = parts[0];
                try {
                    port = Integer.parseInt(parts[1]);
                } catch (NumberFormatException e) {
                    port = protocol.equals("https") ? 443 : 80;
                }
            } else if (host != null) {
                port = protocol.equals("https") ? 443 : 80;
            }

            if (host != null) {
                // Create a descriptive tab name for the Repeater
                String tabName = "BTP - " + protocol + "://" + host + ":" + port;

                // Use the correct sendToRepeater method signature with String tab name
                montoya.repeater().sendToRepeater(request, tabName);
                logger.info("[BTPHttpRequestEditor] Sent updated request to Repeater with tab name: " + tabName);
                JOptionPane.showMessageDialog(mainPanel, "Updated request sent to Repeater (tab: " + tabName + "). Please use the new tab.");
            } else {
                // Use the simpler sendToRepeater method when no target available
                montoya.repeater().sendToRepeater(request, "BTP Request");
                JOptionPane.showMessageDialog(mainPanel, "Host header not found, sent to Repeater with default tab name.");
            }
        } catch (Exception ex) {
            logger.log(java.util.logging.Level.SEVERE, "[BTPHttpRequestEditor] Failed to send to Repeater with target: " + ex.getMessage(), ex);
            JOptionPane.showMessageDialog(mainPanel, "Failed to send to Repeater: " + ex.getMessage());
        }
    }



    /**
     * Converts a header name to HTTP "Camel-Case" (first letter and every letter after a dash capitalized).
     * Example: "content-length" -> "Content-Length"
     * @param headerName The original header name.
     * @return The header name in HTTP Camel-Case.
     */
    private static String toHttpCamelCase(String headerName) {
        if (headerName == null || headerName.isEmpty()) {
            return headerName;
        }
        StringBuilder sb = new StringBuilder(headerName.length());
        boolean capitalize = true;
        for (char c : headerName.toCharArray()) {
            if (capitalize && Character.isLetter(c)) {
                sb.append(Character.toUpperCase(c));
                capitalize = false;
            } else {
                sb.append(Character.toLowerCase(c));
            }
            if (c == '-') {
                capitalize = true;
            }
        }
        return sb.toString();
    }
    /**
     * Converts a JSON message to BlazorPack, called when the "Raw" tab is clicked
     * Just return the existing request body if editor not modified, re-serialize if editor is modified
     * Prompts the user if the request is not using the active circuit.
     * @return - an HttpRequest object containing the BlazorPacked HTTP request/response pair
     */
    @Override
    public HttpRequest getRequest() {
        logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditor] getRequest() called.",
                System.currentTimeMillis(), Thread.currentThread().getName()));
        try {
            // Always use the latest editor contents
            String editorContents = new String(this.editor.getContents().getBytes(), StandardCharsets.ISO_8859_1);
            byte[] editorBytes = editorContents.getBytes(StandardCharsets.ISO_8859_1);

            // Parse the request line and headers from the editor
            HttpRequest updatedRequest = HttpRequest.httpRequest(ByteArray.byteArray(editorBytes));

            // Find the body offset
            int bodyOffset = this.blazorHelper.getBodyOffset(editorBytes);
            if (bodyOffset < 0 || bodyOffset >= editorBytes.length) {
                logger.warning("[BTPHttpRequestEditor] Could not determine body offset; returning as-is.");
                logger.info("[BTPHttpRequestEditor] Full request being sent (raw):\n" + editorContents);
                return updatedRequest;
            }

            // Extract the JSON body
            byte[] jsonBody = ArraySliceHelper.getArraySlice(editorBytes, bodyOffset, editorBytes.length);

            // Try to reserialize the body as BlazorPack
            try {
                JSONArray messages = new JSONArray(new String(jsonBody, StandardCharsets.UTF_8));
                byte[] newBody = this.blazorHelper.blazorPack(messages);
                HttpRequest finalRequest = updatedRequest.withBody(ByteArray.byteArray(newBody));
                logFullRequest(finalRequest, newBody.length);
                return finalRequest;
            } catch (Exception e) {
                // If body is not valid JSON, just return the request as parsed from the editor (headers and body as-is)
                logger.log(Level.WARNING, "[BTPHttpRequestEditor] Body not valid JSON, sending as-is: " + e.getMessage(), e);
                logFullRequest(updatedRequest, jsonBody.length);
                return updatedRequest;
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, "[BTPHttpRequestEditor] getRequest() failed: " + ex.getMessage(), ex);
            JOptionPane.showMessageDialog(mainPanel, "Failed to build request from editor: " + ex.getMessage());
            return null;
        }
    }

    private void logFullRequest(HttpRequest request, int bodyLength) {
        StringBuilder sb = new StringBuilder();
        sb.append(request.method()).append(" ").append(request.path()).append(" ").append(request.httpVersion()).append("\r\n");
        for (HttpHeader header : request.headers()) {
            sb.append(header.name()).append(": ").append(header.value()).append("\r\n");
        }
        sb.append("\r\n");
        sb.append("[BODY: ").append(bodyLength).append(" bytes]");
        logger.info("[BTPHttpRequestEditor] Full request being sent (headers + body):\n" + sb.toString());
    }




    /**
     * Converts a given BlazorPack message to JSON, called when the "BTP" tab is clicked.
     * Handles filtering: disables the editor and shows a message if not a BlazorPack request.
     * @param requestResponse The request to deserialize from BlazorPack to JSON.
     */
    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditor] setRequestResponse() called. URL: %3$s",
                System.currentTimeMillis(), Thread.currentThread().getName(), (requestResponse != null ? safeUrl(requestResponse) : "null")));
        this.reqResp = requestResponse;

        // Filtering: Only handle BlazorPack requests
        boolean isBlazorPack = requestResponse != null &&
                requestResponse.request() != null &&
                requestResponse.request().body() != null &&
                requestResponse.request().body().length() > 0 &&
                requestResponse.url() != null &&
                requestResponse.url().contains(BTPConstants.BLAZOR_URL);

        if (!isBlazorPack) {
            this.editor.setContents(ByteArray.byteArray("Not a BlazorPack request.".getBytes(StandardCharsets.UTF_8)));
            this.editor.setEditable(false);
            logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditor] Not a BlazorPack request. Editor disabled.",
                    System.currentTimeMillis(), Thread.currentThread().getName()));
            SwingUtilities.invokeLater(this::updateCircuitStatusLabel);
            return;
        }

        this.editor.setEditable(true);

        byte[] body = requestResponse.request().body().getBytes();
        ArrayList<GenericMessage> messages = this.blazorHelper.blazorUnpack(body);
        ByteArrayOutputStream outstream = new ByteArrayOutputStream();
        try {
            String jsonStrMessages = this.blazorHelper.messageArrayToString(messages);
            outstream.write(jsonStrMessages.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            String msg = "[-] setRequestResponse - Exception while writing bytes to buffer: " + e.getMessage();
            this.logging.logToError(msg);
            logger.log(Level.WARNING, "[BTPHttpRequestEditor] " + msg, e);
            SwingUtilities.invokeLater(this::updateCircuitStatusLabel);
            return;
        }
        HttpRequest newReq = this.reqResp.request().withBody(ByteArray.byteArray(outstream.toByteArray()));
        this.reqResp = HttpRequestResponse.httpRequestResponse(newReq, this.reqResp.response());
        this.editor.setContents(this.reqResp.request().toByteArray());

        logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditor] setRequestResponse() completed. Editor contents set.",
                System.currentTimeMillis(), Thread.currentThread().getName()));

        SwingUtilities.invokeLater(this::updateCircuitStatusLabel);
    }
    /**
     * Update the request URL's id parameter to the active circuit token,
     * and replace the Cookie header value with the latestCookie from ActiveCircuitTracker.
     * Ensures Host and Cookie headers are present and capitalized, and all other headers retain their original case and order.
     * The editor UI will display headers exactly as constructed.
     */
    private void updateRequestUrlWithActiveCircuit() {
        String latestToken = ActiveCircuitTracker.getLatestToken();
        String latestCookie = ActiveCircuitTracker.getLatestCookie();

        if (latestToken == null) {
            JOptionPane.showMessageDialog(mainPanel, "No active circuit token available.");
            return;
        }
        if (latestCookie == null) {
            JOptionPane.showMessageDialog(mainPanel, "No active circuit cookie available.");
            return;
        }

        try {
            if (this.reqResp != null && this.reqResp.request() != null) {
                HttpRequest original = this.reqResp.request();
                String url = original.url();

                // Update id in URL
                String updatedUrl = url.replaceAll("id=[^&]+", "id=" + latestToken);

                // Extract the path and query from the updated URL
                int pathStart = updatedUrl.indexOf("/", updatedUrl.indexOf("://") + 3);
                String pathAndQuery = pathStart != -1 ? updatedUrl.substring(pathStart) : updatedUrl;

                // Prepare header variables
                String hostHeaderValue = null;
                List<HttpHeader> otherHeaders = new ArrayList<>();
                boolean hostFound = false;
                boolean cookieFound = false;

                List<HttpHeader> headers = original.headers();
                logHeaders("Original", headers);

                for (HttpHeader header : headers) {
                    String name = header.name();
                    logger.info("[BTPHttpRequestEditor][HeaderLoop] Found header: '" + name + "' value: '" + header.value() + "'");
                    if (name.trim().equalsIgnoreCase("Host")) {
                        hostHeaderValue = header.value();
                        hostFound = true;
                    } else if (name.trim().equalsIgnoreCase("Cookie")) {
                        // Skip old cookie header, will add new one below
                        cookieFound = true;
                    } else if (!name.startsWith(":")) {
                        otherHeaders.add(header);
                    }
                }

                // If Host header is missing, extract from URL and log
                if (!hostFound) {
                    try {
                        String hostFromUrl = null;
                        int schemeEnd = updatedUrl.indexOf("://");
                        if (schemeEnd != -1) {
                            int hostStart = schemeEnd + 3;
                            int hostEnd = updatedUrl.indexOf("/", hostStart);
                            if (hostEnd == -1) hostEnd = updatedUrl.length();
                            hostFromUrl = updatedUrl.substring(hostStart, hostEnd);
                        }
                        if (hostFromUrl != null) {
                            hostHeaderValue = hostFromUrl;
                            logger.warning("[BTPHttpRequestEditor][HostRecovery] Host header missing in original headers, recovered from URL: " + hostHeaderValue);
                        }
                    } catch (Exception e) {
                        logger.log(Level.WARNING, "[BTPHttpRequestEditor][HostRecovery] Failed to recover Host from URL: " + updatedUrl, e);
                    }
                }

                // Build the raw HTTP request string
                StringBuilder rawRequest = new StringBuilder();
                // Request line
                rawRequest.append(original.method())
                        .append(" ")
                        .append(pathAndQuery)
                        .append(" ")
                        .append(original.httpVersion())
                        .append("\r\n");

                // Host header (always second line, capitalized)
                if (hostHeaderValue != null) {
                    rawRequest.append("Host: ").append(hostHeaderValue).append("\r\n");
                    logger.info("[BTPHttpRequestEditor][RawRequest] Added Host: " + hostHeaderValue);
                } else {
                    logger.warning("[BTPHttpRequestEditor][RawRequest] Host header is STILL missing after recovery attempt!");
                }

                // Cookie header (always third line, capitalized, always set to latestCookie)
                rawRequest.append("Cookie: ").append(latestCookie).append("\r\n");
                logger.info("[BTPHttpRequestEditor][RawRequest] Set Cookie header to latestCookie: " + latestCookie);

                // All other headers (skip Host and Cookie, preserve original case and order)
                for (HttpHeader header : otherHeaders) {
                    String camelCaseName = toHttpCamelCase(header.name());
                    rawRequest.append(camelCaseName).append(": ").append(header.value()).append("\r\n");
                }
                rawRequest.append("\r\n");

                // Write body if present
                ByteArray body = original.body();
                if (body != null && body.length() > 0) {
                    rawRequest.append(body.toString());
                }

                logger.info("[BTPHttpRequestEditor][RawRequest] Final raw request string:\n" + rawRequest);

                // Set the editor contents directly with the raw request string (preserves header case/order in UI)
                this.editor.setContents(ByteArray.byteArray(rawRequest.toString().getBytes(StandardCharsets.ISO_8859_1)));
                logger.info("[BTPHttpRequestEditor] Updated editor contents with correct header case and order.");
// --- Ensure reqResp is updated so the status label reflects the new circuit ---
                try {
                    String updatedEditorContents = new String(this.editor.getContents().getBytes(), StandardCharsets.ISO_8859_1);
                    HttpRequest updatedRequest = HttpRequest.httpRequest(ByteArray.byteArray(updatedEditorContents.getBytes(StandardCharsets.ISO_8859_1)));
                    this.reqResp = HttpRequestResponse.httpRequestResponse(updatedRequest, this.reqResp != null ? this.reqResp.response() : null);
                    logger.info("[BTPHttpRequestEditor] reqResp updated after circuit update for status label sync.");
                } catch (Exception ex) {
                    logger.log(Level.WARNING, "[BTPHttpRequestEditor] Failed to update reqResp after circuit update: " + ex.getMessage(), ex);
                }

                updateCircuitStatusLabel();
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, "[BTPHttpRequestEditor] Failed to update request URL/cookie with active circuit", ex);
            JOptionPane.showMessageDialog(mainPanel, "Failed to update request URL/cookie: " + ex.getMessage());
        }
    }



    /**
     * Helper to safely get URL for logging without throwing.
     */
    private String safeUrl(HttpRequestResponse requestResponse) {
        try {
            return requestResponse.url();
        } catch (Exception e) {
            return "MALFORMED_URL";
        }
    }

    /**
     * Gets the caption for the editor tab.
     * @return "BTP" - BlazorTrafficProcessor
     */
    @Override
    public String caption() {
        logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditor] caption() called.",
                System.currentTimeMillis(), Thread.currentThread().getName()));
        return BTPConstants.CAPTION;
    }

    /**
     * Gets the UI component for the editor tab.
     * @return The editor's UI component.
     */
    @Override
    public Component uiComponent() {
        logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditor] uiComponent() called.",
                System.currentTimeMillis(), Thread.currentThread().getName()));
        return this.mainPanel;
    }

    /**
     * Get the selected data within the editor.
     * @return The editor's selection object.
     */
    @Override
    public Selection selectedData() {
        logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditor] selectedData() called.",
                System.currentTimeMillis(), Thread.currentThread().getName()));
        return this.editor.selection().get();
    }

    /**
     * Check if the editor has been modified. If not, the getHttpRequest function is not called.
     * @return true if modified, false otherwise.
     */
    @Override
    public boolean isModified() {
        boolean modified = this.editor.isModified();
        logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditor] isModified() called. Result: %3$s",
                System.currentTimeMillis(), Thread.currentThread().getName(), modified));
        return modified;
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditor] isEnabledFor() called. URL: %3$s",
                System.currentTimeMillis(), Thread.currentThread().getName(),
                (requestResponse != null ? safeUrl(requestResponse) : "null")));

        if (requestResponse == null || requestResponse.request() == null) {
            logger.info("[BTPHttpRequestEditor] isEnabledFor: requestResponse or request is null.");
            return false;
        }
        if (requestResponse.request().body() == null || requestResponse.request().body().length() == 0) {
            logger.info("[BTPHttpRequestEditor] isEnabledFor: request body is null or empty.");
            return false;
        }
        String url;
        try {
            url = requestResponse.url();
        } catch (Exception e) {
            logger.log(Level.WARNING, "[BTPHttpRequestEditor] isEnabledFor: Exception getting URL: " + e.getMessage(), e);
            return false;
        }
        if (url == null) {
            logger.info("[BTPHttpRequestEditor] isEnabledFor: url is null.");
            return false;
        }
        if (!url.contains(BTPConstants.BLAZOR_URL)) {
            logger.info("[BTPHttpRequestEditor] isEnabledFor: url does not contain BLAZOR_URL (" + BTPConstants.BLAZOR_URL + ").");
            return false;
        }
        logger.info("[BTPHttpRequestEditor] isEnabledFor: returning true.");
        return true;
    }

    private String extractIdFromUrl() {
        if (this.reqResp != null && this.reqResp.request() != null) {
            String url = this.reqResp.request().url();
            int idx = url.indexOf("id=");
            if (idx != -1) {
                int start = idx + 3;
                int end = url.indexOf('&', start);
                if (end == -1) end = url.length();
                return url.substring(start, end);
            }
        }
        return null;
    }
    private void logHeaders(String context, List<HttpHeader> headers) {
        logger.info("[BTPHttpRequestEditor][" + context + "] Headers:");
        for (HttpHeader header : headers) {
            logger.info("[BTPHttpRequestEditor][" + context + "] " + header.name() + ": " + header.value());
        }
    }

    /**
     * Update the request URL's id parameter to the active circuit token.
     * Does not touch the body or parse JSON.
     */



    // --- UI and circuit helpers ---

    private void updateCircuitStatusLabel() {
        String latestToken = ActiveCircuitTracker.getLatestToken();
        String idInUrl = extractIdFromUrl();
        if (latestToken == null) {
            circuitStatusLabel.setText("No active circuit detected.");
            circuitStatusLabel.setForeground(Color.GRAY);
            updateCircuitButton.setEnabled(false);
        } else if (idInUrl == null) {
            circuitStatusLabel.setText("No id parameter in URL. Active: " + latestToken);
            circuitStatusLabel.setForeground(Color.RED);
            updateCircuitButton.setEnabled(false);
        } else if (latestToken.equals(idInUrl)) {
            circuitStatusLabel.setText("Request uses active circuit.");
            circuitStatusLabel.setForeground(new Color(0, 128, 0)); // Dark green
            updateCircuitButton.setEnabled(false);
        } else {
            circuitStatusLabel.setText("Request does NOT use active circuit! (Active: " + latestToken + ")");
            circuitStatusLabel.setForeground(Color.RED);
            updateCircuitButton.setEnabled(true);
        }
    }
}
