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
                } catch (Exception ex) {
                    logger.log(Level.SEVERE, "[BTPHttpRequestEditor] Error updating to active circuit", ex);
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
     * Converts a JSON message to BlazorPack, called when the "Raw" tab is clicked
     * Just return the existing request body if editor not modified, re-serialize if editor is modified
     * Prompts the user if the request is not using the active circuit.
     * @return - an HttpRequest object containing the BlazorPacked HTTP request/response pair
     */
    @Override
    public HttpRequest getRequest() {
        logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditor] getRequest() called. isModified: %3$s",
                System.currentTimeMillis(), Thread.currentThread().getName(), this.editor.isModified()));

        // Prompt if not using active circuit
        String latestToken = ActiveCircuitTracker.getLatestToken();
        String idInUrl = extractIdFromUrl();
        if (latestToken != null && idInUrl != null && !latestToken.equals(idInUrl)) {
            int result = JOptionPane.showConfirmDialog(mainPanel,
                    "This request is not using the active circuit.\nReplace id with the active one?",
                    "Update to Active Circuit", JOptionPane.YES_NO_OPTION);
            if (result == JOptionPane.YES_OPTION) {
                updateRequestUrlWithActiveCircuit();
            }
        }

        byte[] body;
        if (this.editor.isModified()) {
            int bodyOffset = this.blazorHelper.getBodyOffset(this.editor.getContents().getBytes());
            body = ArraySliceHelper.getArraySlice(this.editor.getContents().getBytes(), bodyOffset, this.editor.getContents().length());
        } else {
            body = this.reqResp.request().body().getBytes();
        }
        if (body == null || body.length == 0) {
            String msg = "[-] getRequest: The selected editor body is empty/null.";
            this.logging.logToError(msg);
            logger.warning("[BTPHttpRequestEditor] " + msg);
            return null;
        }
        JSONArray messages;
        byte[] newBody;
        try {
            messages = new JSONArray(new String(body));
            newBody = this.blazorHelper.blazorPack(messages);
        } catch (JSONException e) {
            String msg = "[-] getRequest - JSONException while parsing JSON array: " + e.getMessage();
            this.logging.logToError(msg);
            logger.log(Level.WARNING, "[BTPHttpRequestEditor] " + msg, e);
            return null;
        } catch (Exception e) {
            String msg = "[-] getRequest - Unexpected exception while getting the request: " + e.getMessage();
            this.logging.logToError(msg);
            logger.log(Level.SEVERE, "[BTPHttpRequestEditor] " + msg, e);
            return null;
        }
        logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditor] getRequest() returning new HttpRequest with body length: %3$d",
                System.currentTimeMillis(), Thread.currentThread().getName(), (newBody != null ? newBody.length : 0)));
        return this.reqResp.request().withBody(ByteArray.byteArray(newBody));
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
     * Update the request URL's id parameter to the active circuit token.
     * Ensures Host and Cookie headers are present and capitalized, and all other headers retain their original case and order.
     * The editor UI will display headers exactly as constructed.
     */
    private void updateRequestUrlWithActiveCircuit() {
        String latestToken = ActiveCircuitTracker.getLatestToken();
        if (latestToken == null) {
            JOptionPane.showMessageDialog(mainPanel, "No active circuit token available.");
            return;
        }
        try {
            if (this.reqResp != null && this.reqResp.request() != null) {
                HttpRequest original = this.reqResp.request();
                String url = original.url();
                String oldToken = extractIdFromUrl();

                List<HttpHeader> headers = original.headers();
                logHeaders("Original", headers);

                // Update id in URL
                String updatedUrl = url.replaceAll("id=[^&]+", "id=" + latestToken);

                // Extract the path and query from the updated URL
                int pathStart = updatedUrl.indexOf("/", updatedUrl.indexOf("://") + 3);
                String pathAndQuery = pathStart != -1 ? updatedUrl.substring(pathStart) : updatedUrl;

                // Prepare header variables
                String hostHeaderValue = null;
                StringBuilder cookieHeaderValue = new StringBuilder();
                List<HttpHeader> otherHeaders = new ArrayList<>();

                // Track if Host/Cookie were found in original headers
                boolean hostFound = false;
                boolean cookieFound = false;

                for (HttpHeader header : headers) {
                    String name = header.name();
                    logger.info("[BTPHttpRequestEditor][HeaderLoop] Found header: '" + name + "' value: '" + header.value() + "'");
                    if (name.trim().equalsIgnoreCase("Host")) {
                        hostHeaderValue = header.value();
                        hostFound = true;
                        logger.info("[BTPHttpRequestEditor][HeaderLoop] Matched Host header: '" + name + "' value: '" + hostHeaderValue + "'");
                    } else if (name.trim().equalsIgnoreCase("Cookie")) {
                        if (cookieHeaderValue.length() > 0) {
                            cookieHeaderValue.append("; ");
                        }
                        cookieHeaderValue.append(header.value());
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

                // Update the cookie value if it contains the old token
                if (cookieHeaderValue.length() > 0 && oldToken != null) {
                    String updatedCookieValue = cookieHeaderValue.toString().replace(oldToken, latestToken);
                    cookieHeaderValue = new StringBuilder(updatedCookieValue);
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

                // Cookie header (always third line, capitalized)
                if (cookieHeaderValue.length() > 0) {
                    rawRequest.append("Cookie: ").append(cookieHeaderValue).append("\r\n");
                    logger.info("[BTPHttpRequestEditor][RawRequest] Added Cookie: " + cookieHeaderValue);
                } else {
                    logger.info("[BTPHttpRequestEditor][RawRequest] No Cookie header to add.");
                }

                // All other headers (skip Host and Cookie, preserve original case and order)
                for (HttpHeader header : otherHeaders) {
                    rawRequest.append(header.name()).append(": ").append(header.value()).append("\r\n");
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

                // Optionally update reqResp for further processing (not for UI)
                this.reqResp = HttpRequestResponse.httpRequestResponse(
                        HttpRequest.httpRequest(rawRequest.toString()), this.reqResp.response()
                );

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
