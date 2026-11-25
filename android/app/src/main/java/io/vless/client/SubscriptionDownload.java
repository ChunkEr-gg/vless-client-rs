package io.vless.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;

final class SubscriptionDownload {
    static final int MAX_BYTES = 1_048_576;

    static final class TooLarge extends IOException {}

    private SubscriptionDownload() {}

    static byte[] read(String address) throws IOException {
        URL url = new URL(address);
        for (int redirects = 0; redirects <= 5; redirects++) {
            checkInterrupted();
            if (!"https".equalsIgnoreCase(url.getProtocol()) || url.getHost().isEmpty())
                throw new IOException("Expected an HTTPS subscription URL");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setConnectTimeout(15000);
            connection.setReadTimeout(15000);
            connection.setUseCaches(false);
            connection.setInstanceFollowRedirects(false);
            try {
                int status = connection.getResponseCode();
                if (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) {
                    String location = connection.getHeaderField("Location");
                    if (location == null)
                        throw new IOException("Missing subscription redirect");
                    url = new URL(url, location);
                    continue;
                }
                if (status < 200 || status >= 300)
                    throw new IOException("Subscription request failed");
                if (connection.getContentLengthLong() > MAX_BYTES)
                    throw new TooLarge();
                try (InputStream input = connection.getInputStream()) {
                    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                    byte[] chunk = new byte[8192];
                    while (true) {
                        checkInterrupted();
                        int count = input.read(chunk);
                        if (count == -1)
                            return bytes.toByteArray();
                        if (count > MAX_BYTES - bytes.size())
                            throw new TooLarge();
                        bytes.write(chunk, 0, count);
                    }
                }
            } finally {
                connection.disconnect();
            }
        }
        throw new IOException("Too many subscription redirects");
    }

    private static void checkInterrupted() throws InterruptedIOException {
        if (Thread.currentThread().isInterrupted())
            throw new InterruptedIOException();
    }
}
