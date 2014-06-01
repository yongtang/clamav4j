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
import java.nio.channels.AsynchronousChannelGroup;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;

public class ClamAVAsync implements AutoCloseable {

    private final AsynchronousChannelGroup asynchronousChannelGroup;
    private InetSocketAddress address;
    private int timeout;

    public ClamAVAsync(InetSocketAddress address, int timeout) throws IOException {
        this.asynchronousChannelGroup = AsynchronousChannelGroup.withThreadPool(Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors()));
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

    public <A> void scan(InputStream inputStream, A attachment, ClamAVAsyncCallback<A> callback) throws IOException {
        AsynchronousSocketChannel asynchronousSocketChannel = AsynchronousSocketChannel.open(this.asynchronousChannelGroup);
        asynchronousSocketChannel.connect(this.address, new ClamAVAsyncObject(inputStream, attachment, callback, asynchronousSocketChannel), new ClamAVAsyncObjectCompletionHandlerConnect());
    }
    
    public boolean ping() {
        return ClamAV.ping(this.address, this.timeout);
    }

    @Override
    public void close() {
        this.asynchronousChannelGroup.shutdown();
        try {
            this.asynchronousChannelGroup.awaitTermination(this.timeout == 0 ? Long.MAX_VALUE : this.timeout, TimeUnit.MILLISECONDS);
        } catch (InterruptedException ex) {
            Logger.getLogger(ClamAVAsync.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    static protected class ClamAVAsyncObject<A> {

        protected final InputStream inputStream;
        protected final A attachment;
        protected final ClamAVAsyncCallback<A> callback;
        protected final AsynchronousSocketChannel asynchronousSocketChannel;
        protected final ByteBuffer head = ByteBuffer.wrap(ClamAV.INSTREAM);
        protected byte[] buffer = new byte[ClamAV.CHUNK];
        protected int chunk = 0;
        protected ByteBuffer data;
        ByteBuffer size = ByteBuffer.allocate(4);
        ByteBuffer read = ByteBuffer.allocate(1024);

        protected ClamAVAsyncObject(InputStream inputStream, A attachment, ClamAVAsyncCallback<A> callback, AsynchronousSocketChannel asynchronousSocketChannel) {
            this.inputStream = inputStream;
            this.attachment = attachment;
            this.callback = callback;
            this.asynchronousSocketChannel = asynchronousSocketChannel;
        }

        protected void completed(String result) {
            try {
                this.asynchronousSocketChannel.close();
            } catch (IOException ex) {
                Logger.getLogger(ClamAVAsync.class.getName()).log(Level.SEVERE, null, ex);
            }
            this.callback.completed(result, attachment, inputStream);
        }

        protected void failed(Throwable exc) {
            try {
                this.asynchronousSocketChannel.close();
            } catch (IOException ex) {
                Logger.getLogger(ClamAVAsync.class.getName()).log(Level.SEVERE, null, ex);
            }
            this.callback.failed(exc, attachment, inputStream);
        }
    }

    static protected class ClamAVAsyncObjectCompletionHandlerRead implements CompletionHandler<Integer, ClamAVAsyncObject> {

        @Override
        public void completed(Integer result, ClamAVAsyncObject attachment) {
            for (int index = 0; index < attachment.read.position(); index++) {
                if (attachment.read.array()[index] == 0) {
                    String status = new String(attachment.read.array()).substring(0, index);
                    Matcher matcher = ClamAV.FOUND.matcher(status);
                    if (matcher.matches()) {
                        attachment.completed(matcher.group(1));
                    } else if (ClamAV.OK.equals(status)) {
                        attachment.completed("OK");
                    } else {
                        attachment.failed(new ClamAVException(status));
                    }
                    return;
                }
            }

            attachment.asynchronousSocketChannel.read(attachment.read, attachment, this);
        }

        @Override
        public void failed(Throwable exc, ClamAVAsyncObject attachment) {
            attachment.failed(exc);
        }
    }

    static protected class ClamAVAsyncObjectCompletionHandlerData implements CompletionHandler<Integer, ClamAVAsyncObject> {

        @Override
        public void completed(Integer result, ClamAVAsyncObject attachment) {
            if (attachment.head.remaining() != 0) {
                attachment.asynchronousSocketChannel.write(attachment.data, attachment, this);
            } else {
                if (attachment.chunk == ClamAV.CHUNK) {
                    try {
                        if ((attachment.chunk = attachment.inputStream.read(attachment.buffer)) < 0) {
                            attachment.chunk = 0;
                        }
                        attachment.data = ByteBuffer.wrap(attachment.buffer, 0, attachment.chunk);
                        attachment.size.clear();
                        attachment.size.putInt(attachment.chunk).flip();
                        attachment.asynchronousSocketChannel.write(attachment.size, attachment, new ClamAVAsyncObjectCompletionHandlerSize());
                    } catch (IOException ex) {
                        Logger.getLogger(ClamAVAsync.class.getName()).log(Level.SEVERE, null, ex);
                        this.failed(ex, attachment);
                    }
                } else {
                    attachment.chunk = 0;
                    attachment.size.clear();
                    attachment.size.putInt(attachment.chunk).flip();
                    attachment.asynchronousSocketChannel.write(attachment.size, attachment, new ClamAVAsyncObjectCompletionHandlerSize());
                }
            }
        }

        @Override
        public void failed(Throwable exc, ClamAVAsyncObject attachment) {
            attachment.failed(exc);
        }
    }

    static protected class ClamAVAsyncObjectCompletionHandlerSize implements CompletionHandler<Integer, ClamAVAsyncObject> {

        @Override
        public void completed(Integer result, ClamAVAsyncObject attachment) {
            if (attachment.head.remaining() != 0) {
                attachment.asynchronousSocketChannel.write(attachment.size, attachment, this);
            } else {
                if (attachment.chunk == 0) {
                    attachment.asynchronousSocketChannel.read(attachment.read, attachment, new ClamAVAsyncObjectCompletionHandlerRead());
                } else {
                    attachment.asynchronousSocketChannel.write(attachment.data, attachment, new ClamAVAsyncObjectCompletionHandlerData());
                }
            }
        }

        @Override
        public void failed(Throwable exc, ClamAVAsyncObject attachment) {
            attachment.failed(exc);
        }
    }

    static protected class ClamAVAsyncObjectCompletionHandlerHead implements CompletionHandler<Integer, ClamAVAsyncObject> {

        @Override
        public void completed(Integer result, ClamAVAsyncObject attachment) {
            if (attachment.head.remaining() != 0) {
                attachment.asynchronousSocketChannel.write(attachment.head, attachment, this);
            } else {
                try {
                    if ((attachment.chunk = attachment.inputStream.read(attachment.buffer)) < 0) {
                        attachment.chunk = 0;
                    }
                    attachment.data = ByteBuffer.wrap(attachment.buffer, 0, attachment.chunk);
                    attachment.size.clear();
                    attachment.size.putInt(attachment.chunk).flip();
                    attachment.asynchronousSocketChannel.write(attachment.size, attachment, new ClamAVAsyncObjectCompletionHandlerSize());
                } catch (IOException ex) {
                    Logger.getLogger(ClamAVAsync.class.getName()).log(Level.SEVERE, null, ex);
                    this.failed(ex, attachment);
                }
            }
        }

        @Override
        public void failed(Throwable exc, ClamAVAsyncObject attachment) {
            attachment.failed(exc);
        }
    }

    static protected class ClamAVAsyncObjectCompletionHandlerConnect implements CompletionHandler<Void, ClamAVAsyncObject> {

        @Override
        public void completed(Void result, ClamAVAsyncObject attachment) {
            attachment.asynchronousSocketChannel.write(attachment.head, attachment, new ClamAVAsyncObjectCompletionHandlerHead());
        }

        @Override
        public void failed(Throwable exc, ClamAVAsyncObject attachment) {
            attachment.failed(exc);
        }
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java program [--host <host>] [--port <port>] [--timeout <timeout>] [--ping] [<file/directory>]");
            return;
        }

        int timeout = ClamAV.defaultTimeout;
        int port = ClamAV.defaultPort;
        String host = ClamAV.defaultHost;
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
            } else if ("--ping".equals(args[index])) {
                ping = true;
            } else {
                System.out.println("Usage: java program [--host <host>] [--port <port>] [--timeout <timeout>] <file/directory>");
                return;
            }
        }
        try (final ClamAVAsync clamAVAsync = new ClamAVAsync(new InetSocketAddress(host, port), timeout)) {
            if (ping || ("--ping".equals(args[args.length - 1]))) {
                System.out.println(clamAVAsync.getAddress() + ": " + (clamAVAsync.ping() ? "ALIVE" : "DOWN"));
            } else {
                final Path path = Paths.get(args[args.length - 1]);
                try {
                    Files.walkFileTree(path, new SimpleFileVisitor<Path>() {
                        @Override
                        public FileVisitResult visitFile(Path path, BasicFileAttributes basicFileAttributes) throws IOException {
                            try {
                                InputStream inputStream = new FileInputStream(path.toFile());
                                clamAVAsync.scan(inputStream, path.toString(), new ClamAVAsyncCallback<String>() {

                                    @Override
                                    public void completed(String result, String attachment, InputStream inputStream) {
                                        System.out.println(attachment + ": " + ("OK".equals(result) ? "OK" : (result + " FOUND")));
                                        try {
                                            inputStream.close();
                                        } catch (IOException ex) {
                                            Logger.getLogger(ClamAVAsync.class.getName()).log(Level.SEVERE, null, ex);
                                        }
                                    }

                                    @Override
                                    public void failed(Throwable exc, String attachment, InputStream inputStream) {
                                        System.out.println(attachment + ": " + exc);
                                        try {
                                            inputStream.close();
                                        } catch (IOException ex) {
                                            Logger.getLogger(ClamAVAsync.class.getName()).log(Level.SEVERE, null, ex);
                                        }
                                    }
                                });
                            } catch (IOException ex) {
                                System.out.println(path + ": " + ex);
                                Logger.getLogger(ClamAVAsync.class.getName()).log(Level.SEVERE, null, ex);
                            }
                            return FileVisitResult.CONTINUE;
                        }
                    });
                } catch (IOException ex) {
                    Logger.getLogger(ClamAVAsync.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        } catch (IOException ex) {
            Logger.getLogger(ClamAVAsync.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
