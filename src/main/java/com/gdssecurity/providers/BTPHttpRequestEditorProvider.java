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
package com.gdssecurity.providers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import com.gdssecurity.editors.BTPHttpRequestEditor;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Provides a custom HTTP request editor tab for BlazorPack requests.
 * Implements the HttpRequestEditorProvider interface for Burp Suite Montoya API.
 */
public class BTPHttpRequestEditorProvider implements HttpRequestEditorProvider {

    private static final Logger logger = Logger.getLogger(BTPHttpRequestEditorProvider.class.getName());
    private final MontoyaApi montoya;

    /**
     * Constructs a BTPHttpRequestEditorProvider.
     * @param api An instance of the Montoya API.
     */
    public BTPHttpRequestEditorProvider(MontoyaApi api) {
        this.montoya = api;
        logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditorProvider] Initialized.",
                System.currentTimeMillis(), Thread.currentThread().getName()));
    }

    /**
     * Returns a newly created HttpRequestEditor for each request.
     * @param editorContext Details about the context that is requiring a request editor.
     * @return The newly created editor object.
     */
    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext editorContext) {
        logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditorProvider] provideHttpRequestEditor called. EditorMode: %3$s",
                System.currentTimeMillis(), Thread.currentThread().getName(), editorContext.editorMode()));
        try {
            return new BTPHttpRequestEditor(this.montoya, editorContext.editorMode());
        } catch (Exception ex) {
            logger.log(Level.SEVERE, String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditorProvider] Exception creating editor: %3$s",
                    System.currentTimeMillis(), Thread.currentThread().getName(), ex.getMessage()), ex);
            return null;
        }
    }
}
