/**
 * Copyright 2023 Aon plc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.gdssecurity.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import com.gdssecurity.helpers.BTPConstants;
import com.gdssecurity.helpers.ActiveCircuitTracker;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.List;


/**
 * Class to handle the downgrade from WS to LongPolling (HTTP)
 * and track the latest connectionToken from negotiate responses.
 */
public class BTPHttpResponseHandler implements ProxyResponseHandler {

    private final MontoyaApi _montoya;
    private final Logging _logging;
    private final JSONArray modifiedTransports;
    private static final Logger logger = Logger.getLogger("BTP");

    /**
     * Constructor for the BTPHttpResponseHandler object
     * @param montoyaApi - an instance of the Burp Montoya APIs
     */
    public BTPHttpResponseHandler(MontoyaApi montoyaApi) {
        this._montoya = montoyaApi;
        this._logging = montoyaApi.logging();
        this.modifiedTransports = BTPConstants.DOWNGRADED_TRANSPORTS;
    }

    /**
     * Handles the downgrade by listening for matching HTTP responses and auto-modifying them to omit WS.
     * Also tracks the latest connectionToken from negotiate responses.
     * @param interceptedResponse - An object containing the intercepted HTTP response
     * @return the downgraded body if applicable, otherwise just let the response go through un-touched
     */
    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        // Highlight
        if (interceptedResponse.statedMimeType() == MimeType.APPLICATION_UNKNOWN && interceptedResponse.body().length() != 0) {
            interceptedResponse.annotations().setHighlightColor(HighlightColor.CYAN);
        }

        // Handle Blazor Negotiation
        String url = "";
        try {
            url = interceptedResponse.initiatingRequest().url();
        } catch (Exception e) {
            _logging.logToError("[BTPHttpResponseHandler] Could not get URL from initiating request: " + e.getMessage());
        }

        if (url == null || !url.contains(BTPConstants.NEGOTIATE_URL) || interceptedResponse.statedMimeType() != MimeType.JSON) {
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }

        try {
            String bodyStr = interceptedResponse.bodyToString();
            JSONObject body = new JSONObject(bodyStr);

            // --- NEW: Track latest connectionToken and Cookie ---
            if (body.has("connectionToken")) {
                String token = body.optString("connectionToken", null);
                if (token != null) {
                    ActiveCircuitTracker.setLatestToken(token);
                    logger.info("[BTPHttpResponseHandler] Updated latest connectionToken: " + token);

                    // Extract Cookie header from initiating request
                    String latestCookie = null;
                    try {
                        List<HttpHeader> headers = interceptedResponse.initiatingRequest().headers();
                        for (HttpHeader header : headers) {
                            if ("cookie".equalsIgnoreCase(header.name())) {
                                latestCookie = header.value();
                                break;
                            }
                        }
                        if (latestCookie != null) {
                            ActiveCircuitTracker.setLatestCookie(latestCookie);
                            logger.info("[BTPHttpResponseHandler] Updated latestCookie: " + latestCookie);
                        } else {
                            logger.info("[BTPHttpResponseHandler] No Cookie header found in initiating request.");
                        }
                    } catch (Exception ex) {
                        logger.log(Level.WARNING, "[BTPHttpResponseHandler] Error extracting Cookie header: " + ex.getMessage(), ex);
                    }
                }
            }

            // --- Existing: Downgrade availableTransports if needed ---
            if (body.has("availableTransports")) {
                boolean wsEnabled = false;
                JSONArray transports = new JSONArray(body.getJSONArray("availableTransports"));
                for (int i = 0; i < transports.length(); i++) {
                    JSONObject transport = transports.getJSONObject(i);
                    if (transport.has("transport") && transport.getString("transport").equals("WebSockets")) {
                        wsEnabled = true;
                    }
                }
                if (!wsEnabled) {
                    // WS not enabled, no need to downgrade
                    return ProxyResponseReceivedAction.continueWith(interceptedResponse);
                } else {
                    body.remove("availableTransports");
                    body.put("availableTransports", this.modifiedTransports);
                    logger.info("[BTPHttpResponseHandler] Downgraded availableTransports for: " + url);
                    return ProxyResponseReceivedAction.continueWith(interceptedResponse.withBody(body.toString()));
                }
            }
        } catch (JSONException jsonE) {
            this._logging.logToError("[-] handleResponseReceived - An error occurred while reading JSON body for downgrade: " + jsonE.getMessage());
            logger.log(Level.WARNING, "[BTPHttpResponseHandler] JSON error: " + jsonE.getMessage(), jsonE);
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        } catch (Exception e) {
            this._logging.logToError("[-] handleResponseReceived - An unexpected exception occurred when performing the downgrade: " + e.getMessage());
            logger.log(Level.SEVERE, "[BTPHttpResponseHandler] Unexpected error: " + e.getMessage(), e);
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }
        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }


    /**
     * Handles the logic for after a response has been processed
     * Just forward along the un-touched response since it was already modified by handleResponseReceived
     * @param interceptedResponse - An object holding the HTTP response right before it is sent
     * @return the un-touched response object
     */
    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }
}
