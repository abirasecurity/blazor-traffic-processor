package com.gdssecurity.util;

import java.util.logging.*;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * BTPLogger provides a singleton Logger instance with a timestamped log file.
 * The log file will not roll over until it reaches 200MB.
 */
public class BTPLogger {
    private static final Logger logger = Logger.getLogger("BTP");

    static {
        logger.setLevel(Level.ALL);
        try {
            // Generate timestamp for filename
            String timestamp = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss").format(new Date());
            String logFilename = "btp-extension-" + timestamp + ".log";
            // 200MB limit, 1 file (no rollover), append mode
            FileHandler fh = new FileHandler(logFilename, 209_715_200, 1, true);
            fh.setFormatter(new SimpleFormatter());
            logger.addHandler(fh);
            logger.log(Level.INFO, String.format("[%s][%s][BTPLogger] Log file initialized: %s",
                    new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()),
                    Thread.currentThread().getName(),
                    logFilename));
        } catch (Exception e) {
            logger.log(Level.WARNING, String.format("[%s][%s][BTPLogger] Failed to set up file handler",
                    new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()),
                    Thread.currentThread().getName()), e);
        }
    }

    /**
     * Returns the singleton Logger instance for BTP.
     * @return Logger instance
     */
    public static Logger getLogger() {
        return logger;
    }
}
