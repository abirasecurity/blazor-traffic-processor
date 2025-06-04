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
package com.gdssecurity;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.logging.Logging;
import com.gdssecurity.handlers.BTPHttpRequestHandler;
import com.gdssecurity.handlers.BTPHttpResponseHandler;
import com.gdssecurity.helpers.BTPConstants;
import com.gdssecurity.providers.BTPContextMenuItemsProvider;
import com.gdssecurity.providers.BTPHttpRequestEditorProvider;
import com.gdssecurity.providers.BTPHttpResponseEditorProvider;
import com.gdssecurity.views.BTPView;

import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 * Class to hold main logic for BlazorTrafficProcessor extension
 */
public class BlazorTrafficProcessor implements BurpExtension, ExtensionUnloadingHandler {

    private MontoyaApi _montoya;
    private Logging logging;
    private static final Logger logger = Logger.getLogger("BTP");

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
     * Setup function that gets called on extension startup. Register all required handlers, providers, etc.
     * @param api The api implementation to access the functionality of burp suite.
     */
    @Override
    public void initialize(MontoyaApi api) {
        logger.info("[BlazorTrafficProcessor] initialize() called. Thread: " + Thread.currentThread().getName());
        try {
            this._montoya = api;
            this._montoya.extension().setName(BTPConstants.EXTENSION_NAME);
            this.logging = this._montoya.logging();
            logger.info("[BlazorTrafficProcessor] Extension name set: " + BTPConstants.EXTENSION_NAME);

            // Request/Response Editor Providers
            BTPHttpRequestEditorProvider requestEditorProvider = new BTPHttpRequestEditorProvider(this._montoya);
            BTPHttpResponseEditorProvider responseEditorProvider = new BTPHttpResponseEditorProvider(this._montoya);
            this._montoya.userInterface().registerHttpRequestEditorProvider(requestEditorProvider);
            logger.info("[BlazorTrafficProcessor] BTPHttpRequestEditorProvider registered.");
            this._montoya.userInterface().registerHttpResponseEditorProvider(responseEditorProvider);
            logger.info("[BlazorTrafficProcessor] BTPHttpResponseEditorProvider registered.");

            // Request/Response Handlers (for Highlighting + Downgrade WS to HTTP)
            BTPHttpResponseHandler downgradeHandler = new BTPHttpResponseHandler(this._montoya);
            this._montoya.proxy().registerResponseHandler(downgradeHandler);
            logger.info("[BlazorTrafficProcessor] BTPHttpResponseHandler registered.");
            BTPHttpRequestHandler highlightHandler = new BTPHttpRequestHandler(this._montoya);
            this._montoya.proxy().registerRequestHandler(highlightHandler);
            logger.info("[BlazorTrafficProcessor] BTPHttpRequestHandler registered.");

            // Setup the BTP tab in BurpSuite (main nav bar)
            BTPView burpTab = new BTPView(this._montoya);
            this._montoya.userInterface().registerSuiteTab(BTPConstants.CAPTION, burpTab);
            logger.info("[BlazorTrafficProcessor] BTPView registered as suite tab.");

            // Setup the right-click menu items
            BTPContextMenuItemsProvider menuItemsProvider = new BTPContextMenuItemsProvider(this._montoya, burpTab);
            this._montoya.userInterface().registerContextMenuItemsProvider(menuItemsProvider);
            logger.info("[BlazorTrafficProcessor] BTPContextMenuItemsProvider registered.");

            this._montoya.extension().registerUnloadingHandler(this);
            logger.info("[BlazorTrafficProcessor] ExtensionUnloadingHandler registered.");

            this.logging.logToOutput(BTPConstants.LOADED_LOG_MSG);
            logger.info("[BlazorTrafficProcessor] Extension loaded: " + BTPConstants.LOADED_LOG_MSG);

        } catch (Exception e) {
            String errMsg = "[BlazorTrafficProcessor] Exception during initialize: " + e.getMessage();
            if (this.logging != null) {
                this.logging.logToError(errMsg);
            }
            logger.log(Level.SEVERE, errMsg, e);
        }
    }

    /**
     * Gets called when the extension is unloaded. No concurrency used, no need to clean up threads.
     */
    @Override
    public void extensionUnloaded() {
        String msg = "[BlazorTrafficProcessor] extensionUnloaded() called. Thread: " + Thread.currentThread().getName();
        logger.info(msg);
        if (this.logging != null) {
            this.logging.logToOutput(BTPConstants.UNLOADED_LOG_MSG);
        }
        logger.info("[BlazorTrafficProcessor] Extension unloaded: " + BTPConstants.UNLOADED_LOG_MSG);
    }
}
