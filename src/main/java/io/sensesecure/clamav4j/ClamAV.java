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

    public boolean ping() {
        return ping(this.address, this.timeout);
    }

    public static boolean ping(InetSocketAddress address, int timeout) {
        try (SocketChannel socketChannel = SocketChannel.open(address)) {
            socketChannel.write((ByteBuffer) ByteBuffer.wrap(PING));

            socketChannel.socket().setSoTimeout(timeout);

            ByteBuffer data = ByteBuffer.allocate(1024);
            socketChannel.read(data);
            String status = new String(data.array());
            status = status.substring(0, status.indexOf(0));
            if (PONG.equals(status)) {
                return true;
            }
        } catch (IOException ex) {
            Logger.getLogger(ClamAV.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
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
        Matcher matcher = FOUND.matcher(status);
        if (matcher.matches()) {
            return matcher.group(1);
        } else if (OK.equals(status)) {
            return "OK";
        }
        throw new ClamAVException(status);
    }
    
    /**
     * Retrieves the ClamAV database version.
     * 
     * @return ClamAV version.
     */
    public ClamAVVersion getVersion() {
        return getVersion(this.address, this.timeout);
    }

    /**
     * Retrieves the ClamAV database version.
     * 
     * @param address Address where the ClamAV is running.
     * @param timeout Timeout for the request.
     * @return ClamAV version.
     */
    public static ClamAVVersion getVersion(InetSocketAddress address, int timeout) {
        try (SocketChannel socketChannel = SocketChannel.open(address)) {
            socketChannel.write((ByteBuffer) ByteBuffer.wrap(VERSION));
            socketChannel.socket().setSoTimeout(timeout);
            ByteBuffer data = ByteBuffer.allocate(1024);
            socketChannel.read(data);
            String status = new String(data.array());
            status = status.substring(0, status.indexOf(0));
            return new ClamAVVersion(status);
        } catch (IOException ex) {
            Logger.getLogger(ClamAV.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java program [--host <host>] [--port <port>] [--timeout <timeout>] [--channel] [--ping] [<file/directory>]");
            return;
        }

        int timeout = defaultTimeout;
        int port = defaultPort;
        String host = defaultHost;
        boolean channel = false;
        boolean ping = false;
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
            } else if ("--ping".equals(args[index])) {
                ping = true;
            } else {
                System.out.println("Usage: java program [--host <host>] [--port <port>] [--timeout <timeout>] <file/directory>");
                return;
            }
        }
        final ClamAV clamAV = new ClamAV(new InetSocketAddress(host, port), timeout);
        if (ping || ("--ping".equals(args[args.length - 1]))) {            
            System.out.println(clamAV.getAddress() + ": " + (clamAV.ping() ? "ALIVE" : "DOWN"));
        } else {
            final boolean channelSelection = channel;
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
                                try (InputStream inputStream = new FileInputStream(path.toFile())) {
                                    String status = clamAV.scan(inputStream);
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
    }

    protected static final byte[] INSTREAM = "zINSTREAM\0".getBytes();
    protected static final Pattern FOUND = Pattern.compile("^stream: (.+) FOUND$");
    protected static final String OK = "stream: OK";
    protected static final int CHUNK = 4096;

    protected static final byte[] PING = "zPING\0".getBytes();
    protected static final String PONG = "PONG";

    protected static final byte[] VERSION = "zVERSION\0".getBytes();

    protected static final int defaultTimeout = 0;
    protected static final int defaultPort = 3310;
    protected static final String defaultHost = "localhost";
}
