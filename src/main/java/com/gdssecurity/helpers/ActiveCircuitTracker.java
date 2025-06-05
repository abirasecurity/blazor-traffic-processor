package com.gdssecurity.helpers;

import java.util.concurrent.atomic.AtomicReference;

public class ActiveCircuitTracker {
    private static final AtomicReference<String> latestToken = new AtomicReference<>(null);

    public static void setLatestToken(String token) {
        latestToken.set(token);
    }

    public static String getLatestToken() {
        return latestToken.get();
    }
}
