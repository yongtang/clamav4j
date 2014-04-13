/*
 * Copyright 2014 sensesecure.io.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.sensesecure.clamav4j;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ClamAV {

    private InetSocketAddress address;
    private int timeout;

    public ClamAV(InetSocketAddress address, int timeout) {
        this.address = address;
        this.timeout = timeout;
    }

    public InetSocketAddress getAddress() {
        return this.address;
    }

    public void setAddress(InetSocketAddress address) {
        this.address = address;
    }

    public int getTimeout() {
        return this.timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public String scan(FileChannel fileChannel) throws IOException, ClamAVException {
        return scan(fileChannel, this.address, this.timeout);
    }

    public String scan(InputStream inputStream) throws IOException, ClamAVException {
        return scan(inputStream, this.address, this.timeout);
    }

    public static String scan(FileChannel fileChannel, InetSocketAddress address, int timeout) throws IOException, ClamAVException {
        try (SocketChannel socketChannel = SocketChannel.open(address)) {
            socketChannel.write((ByteBuffer) ByteBuffer.wrap(INSTREAM));
            ByteBuffer size = ByteBuffer.allocate(4);
            size.clear();
            size.putInt((int) fileChannel.size()).flip();
            socketChannel.write(size);
            fileChannel.transferTo(0, (int) fileChannel.size(), socketChannel);
            size.clear();
            size.putInt(0).flip();
            socketChannel.write(size);

            return scanResult(socketChannel, timeout);
        }
    }

    public static String scan(InputStream inputStream, InetSocketAddress address, int timeout) throws IOException, ClamAVException {
        try (SocketChannel socketChannel = SocketChannel.open(address)) {
            socketChannel.write((ByteBuffer) ByteBuffer.wrap(INSTREAM));
            ByteBuffer size = ByteBuffer.allocate(4);
            byte[] b = new byte[CHUNK];
            int chunk = CHUNK;
            while (chunk == CHUNK) {
                chunk = inputStream.read(b);
                if (chunk > 0) {
                    size.clear();
                    size.putInt(chunk).flip();
                    socketChannel.write(size);
                    socketChannel.write(ByteBuffer.wrap(b, 0, chunk));
                }
            }
            size.clear();
            size.putInt(0).flip();
            socketChannel.write(size);

            return scanResult(socketChannel, timeout);
        }
    }

    private static String scanResult(SocketChannel socketChannel, int timeout) throws IOException, ClamAVException {
        socketChannel.socket().setSoTimeout(timeout);
        ByteBuffer data = ByteBuffer.allocate(1024);
        socketChannel.read(data);
        String status = new String(data.array());
        status = status.substring(0, status.indexOf(0));
        if (OK.equals(status)) {
            return "OK";
        }
        Matcher matcher = FOUND.matcher(status);
        if (matcher.matches()) {
            return matcher.group(1);
        }
        throw new ClamAVException(status);
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java program [--host <host>] [--port <port>] [--timeout <timeout>] [--channel] <file/directory>");
            return;
        }

        int timeout = defaultTimeout;
        int port = defaultPort;
        String host = defaultHost;
        boolean channel = false;
        for (int index = 0; index < args.length - 1; index++) {
            if ("--host".equals(args[index]) && index + 1 < args.length - 1) {
                index++;
                host = args[index];
            } else if ("--port".equals(args[index]) && index + 1 < args.length - 1) {
                index++;
                port = Integer.parseInt(args[index]);
            } else if ("--timeout".equals(args[index]) && index + 1 < args.length - 1) {
                index++;
                timeout = Integer.parseInt(args[index]);
            } else if ("--channel".equals(args[index])) {
                channel = true;
            } else {
                System.out.println("Usage: java program [--host <host>] [--port <port>] [--timeout <timeout>] <file/directory>");
                return;
            }
        }
        final boolean channelSelection = channel;
        final ClamAV clamAV = new ClamAV(new InetSocketAddress(host, port), timeout);
        final Path path = Paths.get(args[args.length - 1]);
        try {
            Files.walkFileTree(path, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path path, BasicFileAttributes basicFileAttributes) throws IOException {
                    try {
                        if (channelSelection) {
                            try (FileChannel fileChannel = FileChannel.open(path)) {
                                String status = clamAV.scan(fileChannel);
                                System.out.println(path + ": " + ("OK".equals(status) ? "OK" : (status + " FOUND")));
                            }
                        } else {
                            try (InputStream fileChannel = new FileInputStream(path.toFile())) {
                                String status = clamAV.scan(fileChannel);
                                System.out.println(path + ": " + ("OK".equals(status) ? "OK" : (status + " FOUND")));
                            }
                        }
                    } catch (ClamAVException | IOException ex) {
                        System.out.println(path + ": " + ex);
                        Logger.getLogger(ClamAV.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException ex) {
            Logger.getLogger(ClamAV.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static final byte[] INSTREAM = "zINSTREAM\0".getBytes();
    private static final Pattern FOUND = Pattern.compile("^stream: (.+) FOUND$");
    private static final String OK = "stream: OK";
    private static final int CHUNK = 4096;

    private static final int defaultTimeout = 0;
    private static final int defaultPort = 3310;
    private static final String defaultHost = "localhost";
}
