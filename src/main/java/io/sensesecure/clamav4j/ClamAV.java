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

import java.io.IOException;
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

    public String scan(FileChannel fileChannel) throws IOException, ClamAVException {
        return scan(fileChannel, this.address, this.timeout);
    }

    public static String scan(FileChannel fileChannel, InetSocketAddress address, int timeout) throws IOException, ClamAVException {
        try (SocketChannel socketChannel = SocketChannel.open(address)) {
            socketChannel.write((ByteBuffer) ByteBuffer.wrap(INSTREAM).position(0));
            socketChannel.write((ByteBuffer) ByteBuffer.allocate(4).putInt((int) fileChannel.size()).position(0));
            fileChannel.transferTo(0, (int) fileChannel.size(), socketChannel);
            socketChannel.write((ByteBuffer) ByteBuffer.allocateDirect(4).position(0));

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

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java program [--host <host>] [--port <port>] [--timeout <timeout>] <file/directory>");
            return;
        }

        int timeout = defaultTimeout;
        int port = defaultPort;
        String host = defaultHost;
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
            } else {
                System.out.println("Usage: java program [--host <host>] [--port <port>] [--timeout <timeout>] <file/directory>");
                return;
            }
        }
        final ClamAV clamAV = new ClamAV(new InetSocketAddress(host, port), timeout);
        final Path path = Paths.get(args[args.length - 1]);
        try {
            Files.walkFileTree(path, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path path, BasicFileAttributes basicFileAttributes) throws IOException {
                    try (FileChannel fileChannel = FileChannel.open(path)) {
                        String status = clamAV.scan(fileChannel);
                        System.out.println(path + ": " + ("OK".equals(status) ? "OK" : (status + " FOUND")));

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

    private static final int defaultTimeout = 0;
    private static final int defaultPort = 3310;
    private static final String defaultHost = "localhost";
}
