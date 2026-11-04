package com.kpgc.timerroot;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.Cipher;

/**
 * Just enough of the ADB host protocol to open one "shell:" stream.
 *
 * This is the classic (non-TLS) channel that adbd exposes on
 * persist.adb.tcp.port, so there is no mDNS, no pairing and no wireless
 * debugging involved. Only CNXN, AUTH, OPEN, WRTE and CLSE are implemented;
 * that is all that is needed to start Shizuku's server and, if that fails, to
 * run the exploit straight from the shell.
 */
final class AdbLocal {

    static final int DEFAULT_PORT = 5555;

    private static final int A_CNXN = 0x4e584e43;
    private static final int A_AUTH = 0x48545541;
    private static final int A_OPEN = 0x4e45504f;
    private static final int A_OKAY = 0x59414b4f;
    private static final int A_CLSE = 0x45534c43;
    private static final int A_WRTE = 0x45545257;
    private static final int A_STLS = 0x534c5453;

    private static final int A_VERSION = 0x01000001;
    private static final int AUTH_TOKEN = 1;
    private static final int AUTH_SIGNATURE = 2;
    private static final int AUTH_RSAPUBLICKEY = 3;

    private static final int MAX_PAYLOAD = 256 * 1024;
    private static final int CONNECT_TIMEOUT_MS = 4000;

    static final class Result {
        /** The command was sent and its stream closed normally. */
        boolean finished;
        /** adbd asked for a key that is not in adb_keys yet. */
        boolean needsAuthorization;
        String output = "";
        String error;

        boolean ok() {
            return finished;
        }

        String describe() {
            if (error != null) {
                return error;
            }
            return output.trim();
        }
    }

    private AdbLocal() {
    }

    static Result shell(String host, int port, PrivateKey key, RSAPublicKey publicKey,
                        String command, long timeoutMs) {
        Result result = new Result();
        long deadline = System.currentTimeMillis() + timeoutMs;
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
            socket.setTcpNoDelay(true);
            DataInputStream in = new DataInputStream(
                    new BufferedInputStream(socket.getInputStream()));
            DataOutputStream out = new DataOutputStream(
                    new BufferedOutputStream(socket.getOutputStream()));

            write(out, A_CNXN, A_VERSION, MAX_PAYLOAD, ascii("host::"));

            boolean authed = false;
            boolean signatureSent = false;
            boolean keySent = false;
            while (!authed) {
                Packet packet = read(in, socket, deadline);
                if (packet == null) {
                    result.error = keySent
                            ? "adbd did not accept TimerRoot's key"
                            : "adb handshake timed out";
                    result.needsAuthorization = keySent;
                    return result;
                }
                if (packet.command == A_CNXN) {
                    authed = true;
                } else if (packet.command == A_AUTH && packet.arg0 == AUTH_TOKEN) {
                    if (!signatureSent) {
                        write(out, A_AUTH, AUTH_SIGNATURE, 0, sign(key, packet.data));
                        signatureSent = true;
                    } else if (!keySent) {
                        // adbd expects the base64 key line as a NUL-terminated
                        // string here, not the binary blob used inside adb_keys.
                        write(out, A_AUTH, AUTH_RSAPUBLICKEY, 0,
                                concat(ascii(AdbKey.publicKeyLine(publicKey)), (byte) 0));
                        keySent = true;
                    } else {
                        result.error = "adbd rejected TimerRoot's key";
                        result.needsAuthorization = true;
                        return result;
                    }
                } else if (packet.command == A_STLS) {
                    result.error = "adbd wants TLS; the classic tcp port is required";
                    return result;
                }
            }
            result.finished = false;

            write(out, A_OPEN, 1, 0, concat(ascii("shell:" + command), (byte) 0));

            int remoteId = -1;
            boolean closed = false;
            ByteArrayOutputStream data = new ByteArrayOutputStream();
            while (!closed) {
                Packet packet = read(in, socket, deadline);
                if (packet == null) {
                    result.error = "timed out waiting for the command";
                    break;
                }
                if (packet.command == A_OKAY) {
                    if (remoteId < 0) {
                        remoteId = packet.arg0;
                    }
                } else if (packet.command == A_WRTE) {
                    if (remoteId < 0) {
                        remoteId = packet.arg0;
                    }
                    if (packet.data != null) {
                        data.write(packet.data);
                    }
                    write(out, A_OKAY, remoteId, 1, null);
                } else if (packet.command == A_CLSE) {
                    closed = true;
                }
            }
            result.output = data.toString("UTF-8");
            result.finished = closed;
            return result;
        } catch (SocketTimeoutException e) {
            result.error = "adb connection timed out";
            return result;
        } catch (IOException e) {
            result.error = "adb: " + e.getMessage();
            return result;
        } finally {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
    }

    private static final class Packet {
        int command;
        int arg0;
        int arg1;
        byte[] data;
    }

    private static Packet read(DataInputStream in, Socket socket, long deadline)
            throws IOException {
        long remaining = deadline - System.currentTimeMillis();
        if (remaining <= 0) {
            return null;
        }
        try {
            socket.setSoTimeout((int) Math.min(Integer.MAX_VALUE, Math.max(1, remaining)));
            byte[] header = new byte[24];
            in.readFully(header);
            ByteBuffer buffer = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN);
            Packet packet = new Packet();
            packet.command = buffer.getInt();
            packet.arg0 = buffer.getInt();
            packet.arg1 = buffer.getInt();
            int length = buffer.getInt();
            buffer.getInt(); // checksum, ignored for protocol version >= 2
            int magic = buffer.getInt();
            if (magic != (packet.command ^ 0xffffffff)) {
                throw new IOException("bad adb packet magic");
            }
            if (length < 0 || length > 1024 * 1024) {
                throw new IOException("bad adb packet length " + length);
            }
            if (length > 0) {
                packet.data = new byte[length];
                in.readFully(packet.data);
            }
            return packet;
        } catch (SocketTimeoutException e) {
            return null;
        } catch (EOFException e) {
            return null;
        }
    }

    private static void write(DataOutputStream out, int command, int arg0, int arg1,
                              byte[] data) throws IOException {
        int length = data == null ? 0 : data.length;
        ByteBuffer header = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        header.putInt(command);
        header.putInt(arg0);
        header.putInt(arg1);
        header.putInt(length);
        header.putInt(0); // checksum: protocol version 2 does not use it
        header.putInt(command ^ 0xffffffff);
        out.write(header.array());
        if (length > 0) {
            out.write(data);
        }
        out.flush();
    }

    /**
     * SHA-1 DigestInfo prefix with no digest, i.e. the DER header that
     * RSA_sign(NID_sha1, ...) prepends.
     */
    private static final byte[] SHA1_DIGEST_INFO = {
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
            0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};

    /**
     * adb does not hash the token: RSA_sign(NID_sha1, token, 20) is called
     * with the 20 raw token bytes, so the PKCS#1 v1.5 block contains the
     * SHA-1 DigestInfo followed by the token itself. Java's "SHA1withRSA"
     * would hash the token and produce a signature adbd rejects, so build
     * the DigestInfo by hand and let the raw RSA cipher pad it.
     */
    private static byte[] sign(PrivateKey key, byte[] token) throws IOException {
        try {
            byte[] digestInfo = new byte[SHA1_DIGEST_INFO.length + token.length];
            System.arraycopy(SHA1_DIGEST_INFO, 0, digestInfo, 0, SHA1_DIGEST_INFO.length);
            System.arraycopy(token, 0, digestInfo, SHA1_DIGEST_INFO.length, token.length);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(digestInfo);
        } catch (Exception e) {
            throw new IOException("cannot sign adb token: " + e, e);
        }
    }

    private static byte[] concat(byte[] data, byte extra) {
        byte[] result = new byte[data.length + 1];
        System.arraycopy(data, 0, result, 0, data.length);
        result[data.length] = extra;
        return result;
    }

    private static byte[] ascii(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }
}
