package com.kpgc.timerroot;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;

/** Downloads the upstream prebuilt exploit without needing a PC. */
final class TimerFetcher {

    private static final int MAX_BYTES = 8 * 1024 * 1024;

    static final class Result {
        final long bytes;
        final String sha256;

        Result(long bytes, String sha256) {
            this.bytes = bytes;
            this.sha256 = sha256;
        }
    }

    private TimerFetcher() {
    }

    static Result download(String url, File dest) throws IOException {
        HttpURLConnection connection = null;
        File tmp = new File(dest.getPath() + ".part");
        try {
            connection = (HttpURLConnection) new URL(url).openConnection();
            connection.setConnectTimeout(15000);
            connection.setReadTimeout(30000);
            connection.setInstanceFollowRedirects(true);
            connection.setRequestProperty("User-Agent", "TimerRoot");
            connection.setRequestProperty("Accept", "application/octet-stream");

            int code = connection.getResponseCode();
            if (code != HttpURLConnection.HTTP_OK) {
                throw new IOException("HTTP " + code);
            }
            long declared = connection.getContentLengthLong();
            if (declared > MAX_BYTES) {
                throw new IOException("file is too large: " + declared + " bytes");
            }

            MessageDigest digest;
            try {
                digest = MessageDigest.getInstance("SHA-256");
            } catch (Exception e) {
                throw new IOException("SHA-256 unavailable", e);
            }

            long total = 0;
            try (InputStream in = connection.getInputStream();
                 FileOutputStream out = new FileOutputStream(tmp)) {
                byte[] buf = new byte[65536];
                int n;
                while ((n = in.read(buf)) > 0) {
                    total += n;
                    if (total > MAX_BYTES) {
                        throw new IOException("file is too large");
                    }
                    out.write(buf, 0, n);
                    digest.update(buf, 0, n);
                }
            }

            checkElf(tmp);
            if (dest.exists() && !dest.delete()) {
                throw new IOException("cannot replace " + dest);
            }
            if (!tmp.renameTo(dest)) {
                throw new IOException("cannot write " + dest);
            }
            return new Result(total, hex(digest.digest()));
        } catch (IOException e) {
            //noinspection ResultOfMethodCallIgnored
            tmp.delete();
            throw e;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private static void checkElf(File file) throws IOException {
        try (FileInputStream in = new FileInputStream(file)) {
            byte[] magic = new byte[4];
            int read = in.read(magic);
            if (read != 4 || magic[0] != 0x7f || magic[1] != 'E'
                    || magic[2] != 'L' || magic[3] != 'F') {
                throw new IOException("download is not an ELF binary");
            }
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
