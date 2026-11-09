package mcpanel;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.bukkit.Bukkit;
import org.bukkit.command.CommandSender;
import org.bukkit.command.ConsoleCommandSender;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * 面板 HTTP 服务：静态页 + 鉴权 API + SSE 日志流 + 指令下发。
 * 安全模型：config.yml 密码 -> nonce+SHA256 校验值挑战应答 -> 内存令牌，登录失败限速。
 */
public final class PanelHttpServer {

    private final PaperPanelPlugin plugin;
    private final ConsoleCapture capture;
    private final String passwordInner; // SHA256(password)
    private final int sessionTtlMinutes;
    private final int loginMaxFails;
    private final int loginLockSeconds;
    private final int backlogLines;

    private final Map<String, Long> sessions = new ConcurrentHashMap<>();
    private final Map<String, Long> nonces = new ConcurrentHashMap<>();
    private final Map<String, Gate> gates = new ConcurrentHashMap<>();
    private final List<SseClient> sseClients = new CopyOnWriteArrayList<>();

    private HttpServer server;
    private ExecutorService executor;

    private static final class Gate {
        int fails;
        long windowStart;
        long lockedUntil;
    }

    private static final class SseClient {
        final OutputStream out;
        final ConsoleCapture.Entry[] lastLog = {null};
        SseClient(OutputStream out) { this.out = out; }
    }

    public PanelHttpServer(PaperPanelPlugin plugin, ConsoleCapture capture, String password,
                           int sessionTtlMinutes, int loginMaxFails, int loginLockSeconds, int backlogLines) {
        this.plugin = plugin;
        this.capture = capture;
        this.passwordInner = sha256(password == null ? "" : password);
        this.sessionTtlMinutes = sessionTtlMinutes;
        this.loginMaxFails = loginMaxFails;
        this.loginLockSeconds = loginLockSeconds;
        this.backlogLines = backlogLines;
    }

    /* ============================== 生命周期 ============================== */

    public void start(String host, int port) throws IOException {
        server = HttpServer.create(new InetSocketAddress(host, port), 0);
        executor = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "PaperPanel-HTTP");
            t.setDaemon(true);
            return t;
        });
        server.setExecutor(executor);
        server.createContext("/", this::handle);
        server.start();
        capture.addListener(this::onLogLine);
    }

    public void stop() {
        capture.removeListener(this::onLogLine);
        for (SseClient c : sseClients) {
            try { c.out.close(); } catch (IOException ignored) {}
        }
        sseClients.clear();
        if (server != null) server.stop(0);
        if (executor != null) executor.shutdownNow();
    }

    /* ============================== SSE 广播 ============================== */

    private void onLogLine(ConsoleCapture.Entry e) {
        broadcast("log", e.toJson());
    }

    public void broadcastStats(String statsJson) {
        broadcast("stats", statsJson);
    }

    private void broadcast(String event, String json) {
        String chunk = "event: " + event + "\ndata: " + json + "\n\n";
        byte[] bytes = chunk.getBytes(StandardCharsets.UTF_8);
        for (SseClient c : sseClients) {
            try {
                synchronized (c) { c.out.write(bytes); c.out.flush(); }
            } catch (IOException ex) {
                sseClients.remove(c);
                try { c.out.close(); } catch (IOException ignored) {}
            }
        }
    }

    /* ============================== 路由 ============================== */

    private void handle(HttpExchange ex) throws IOException {
        String path;
        try {
            path = java.net.URLDecoder.decode(ex.getRequestURI().getPath(), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            sendJson(ex, 400, "{\"error\":\"bad url\"}");
            return;
        }
        try {
            if (path.startsWith("/api/")) {
                handleApi(ex, path);
                return;
            }
            switch (path) {
                case "/":
                case "/index.html":
                    sendResource(ex, "web/index.html", "text/html; charset=utf-8");
                    return;
                case "/app.css":
                    sendResource(ex, "web/app.css", "text/css; charset=utf-8");
                    return;
                case "/app.js":
                    sendResource(ex, "web/app.js", "application/javascript; charset=utf-8");
                    return;
                case "/sha256.js":
                    sendResource(ex, "web/sha256.js", "application/javascript; charset=utf-8");
                    return;
                default:
                    sendJson(ex, 404, "{\"error\":\"not found\"}");
            }
        } catch (Exception e) {
            try { sendJson(ex, 500, "{\"error\":\"服务器内部错误\"}"); } catch (IOException ignored) {}
        }
    }

    private void handleApi(HttpExchange ex, String path) throws IOException {
        String method = ex.getRequestMethod();
        String ip = ex.getRemoteAddress() != null
                ? ex.getRemoteAddress().getAddress().getHostAddress() : "unknown";

        if ("GET".equals(method) && "/api/nonce".equals(path)) {
            String nonce = issueNonce();
            sendJson(ex, 200, "{\"nonce\":\"" + nonce + "\"}");
            return;
        }

        if ("POST".equals(method) && "/api/login".equals(path)) {
            long locked = gateWait(ip);
            if (locked > 0) {
                sendJson(ex, 429, "{\"error\":\"尝试过于频繁，请 " + locked + " 秒后再试\"}");
                return;
            }
            String body = readBody(ex);
            String nonce = JsonUtil.getString(body, "nonce");
            String digest = JsonUtil.getString(body, "digest");
            if (nonce == null || digest == null || !consumeNonce(nonce)) {
                sendJson(ex, 401, "{\"error\":\"登录凭证已过期，请重试\"}");
                return;
            }
            String expected = sha256(nonce + ":" + passwordInner);
            if (!safeEqual(digest.toLowerCase(), expected)) {
                long wait = gateFail(ip);
                sendJson(ex, 401, wait > 0
                        ? "{\"error\":\"密码错误，请 " + wait + " 秒后再试\"}"
                        : "{\"error\":\"密码错误\"}");
                return;
            }
            gates.remove(ip);
            String token = issueToken();
            sendJson(ex, 200, "{\"token\":\"" + token + "\",\"ttlMinutes\":" + sessionTtlMinutes + "}");
            return;
        }

        if ("POST".equals(method) && "/api/logout".equals(path)) {
            String t = bearer(ex);
            if (t != null) sessions.remove(t);
            sendJson(ex, 200, "{\"ok\":true}");
            return;
        }

        // ---- 以下均需鉴权 ----
        if (!checkToken(bearer(ex))) {
            sendJson(ex, 401, "{\"error\":\"未登录或会话已失效\"}");
            return;
        }

        if ("GET".equals(method) && "/api/stats".equals(path)) {
            sendJson(ex, 200, plugin.getStats().toJson());
            return;
        }

        if ("GET".equals(method) && "/api/stream".equals(path)) {
            handleStream(ex);
            return;
        }

        if ("POST".equals(method) && "/api/command".equals(path)) {
            handleCommand(ex);
            return;
        }

        sendJson(ex, 404, "{\"error\":\"not found\"}");
    }

    /* ============================== SSE 流 ============================== */

    private void handleStream(HttpExchange ex) throws IOException {
        Headers h = ex.getResponseHeaders();
        applySecurity(h);
        h.set("Content-Type", "text/event-stream; charset=utf-8");
        ex.sendResponseHeaders(200, 0);
        OutputStream out = ex.getResponseBody();
        SseClient client = new SseClient(out);
        sseClients.add(client);

        StringBuilder sb = new StringBuilder();
        sb.append("event: backlog\ndata: [");
        List<ConsoleCapture.Entry> backlog = capture.backlog(backlogLines);
        for (int i = 0; i < backlog.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(backlog.get(i).toJson());
        }
        sb.append("]\n\n");
        sb.append("event: stats\ndata: ").append(plugin.getStats().toJson()).append("\n\n");
        synchronized (client) { out.write(sb.toString().getBytes(StandardCharsets.UTF_8)); out.flush(); }

        // 心跳保活，直到连接断开
        try {
            while (!Thread.currentThread().isInterrupted()) {
                Thread.sleep(20000);
                synchronized (client) { out.write(": ping\n\n".getBytes(StandardCharsets.UTF_8)); out.flush(); }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (IOException e) {
            sseClients.remove(client);
        }
    }

    /* ============================== 指令下发 ============================== */

    private void handleCommand(HttpExchange ex) throws IOException {
        String body = readBody(ex);
        String cmd = JsonUtil.getString(body, "command");
        if (cmd == null || cmd.trim().isEmpty()) {
            sendJson(ex, 400, "{\"error\":\"指令不能为空\"}");
            return;
        }
        cmd = cmd.trim();
        if (cmd.startsWith("/")) cmd = cmd.substring(1);
        if (cmd.length() > 400) {
            sendJson(ex, 400, "{\"error\":\"指令过长\"}");
            return;
        }
        final String cmdline = cmd;

        Future<String> future = executor.submit(() -> {
            java.util.concurrent.CompletableFuture<String> done = new java.util.concurrent.CompletableFuture<>();
            Bukkit.getScheduler().runTask(plugin, () -> {
                StringBuilder cap = new StringBuilder();
                CommandSender proxy = capturingConsole(cap);
                // 同时采集执行期间的控制台日志窗口（Paper 指令输出多直接进日志管道）
                List<String> window = java.util.Collections.synchronizedList(new ArrayList<>());
                java.util.function.Consumer<ConsoleCapture.Entry> listener = e -> window.add(e.text);
                capture.addListener(listener);
                boolean ok;
                try {
                    ok = Bukkit.dispatchCommand(proxy, cmdline);
                } catch (Throwable t) {
                    capture.removeListener(listener);
                    done.completeExceptionally(t);
                    return;
                }
                final boolean success = ok;
                // 等 5 tick 让异步日志落盘后再合并输出
                Bukkit.getScheduler().runTaskLater(plugin, () -> {
                    capture.removeListener(listener);
                    java.util.LinkedHashSet<String> set = new java.util.LinkedHashSet<>();
                    for (String s : window) {
                        if (s != null && !s.trim().isEmpty()) set.add(s.trim());
                    }
                    if (cap.length() > 0) {
                        for (String s : cap.toString().split("\n")) {
                            if (!s.trim().isEmpty()) set.add(s.trim());
                        }
                    }
                    if (set.isEmpty()) done.complete(success ? "(无输出)" : "(未知指令)");
                    else done.complete(String.join("\n", set));
                }, 5L);
            });
            return done.get(8, TimeUnit.SECONDS);
        });

        try {
            String out = future.get(10, TimeUnit.SECONDS);
            capture.push("INFO", "> " + cmdline + (out != null && !out.startsWith("(") ? " -> " + oneLine(out) : ""));
            sendJson(ex, 200, "{\"ok\":true,\"output\":\"" + JsonUtil.esc(out) + "\"}");
        } catch (TimeoutException e) {
            sendJson(ex, 502, "{\"error\":\"服务器繁忙，指令超时\"}");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            sendJson(ex, 502, "{\"error\":\"指令执行被中断\"}");
        } catch (java.util.concurrent.ExecutionException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            sendJson(ex, 502, "{\"error\":\"指令执行失败: " + JsonUtil.esc(String.valueOf(cause.getMessage())) + "\"}");
        }
    }

    /** 生成一个会捕获输出、权限等同控制台的 CommandSender 代理。 */
    private CommandSender capturingConsole(StringBuilder cap) {
        ConsoleCommandSender console = Bukkit.getConsoleSender();
        return (ConsoleCommandSender) Proxy.newProxyInstance(
                plugin.getClass().getClassLoader(),
                new Class<?>[]{ConsoleCommandSender.class},
                (proxy, method, args) -> {
                    if (method.getName().startsWith("sendMessage") && args != null) {
                        for (Object a : args) {
                            String line = null;
                            if (a instanceof String) {
                                line = (String) a;
                            } else if (a instanceof String[]) {
                                for (String s : (String[]) a) {
                                    if (cap.length() > 0) cap.append('\n');
                                    cap.append(s);
                                }
                            } else if (a instanceof net.kyori.adventure.text.Component) {
                                try {
                                    line = net.kyori.adventure.text.serializer.plain
                                            .PlainTextComponentSerializer.plainText()
                                            .serialize((net.kyori.adventure.text.Component) a);
                                } catch (Throwable ignored) {
                                    line = String.valueOf(a);
                                }
                            }
                            if (line != null) {
                                if (cap.length() > 0) cap.append('\n');
                                cap.append(line);
                            }
                        }
                        return null;
                    }
                    try {
                        return method.invoke(console, args);
                    } catch (InvocationTargetException ite) {
                        throw ite.getCause();
                    }
                });
    }

    private static String oneLine(String s) {
        String first = s.split("\n", 2)[0];
        return first.length() > 160 ? first.substring(0, 160) + "…" : first;
    }

    /* ============================== 鉴权原语 ============================== */

    private String issueToken() {
        String t = randomHex(32);
        sessions.put(t, System.currentTimeMillis() + sessionTtlMinutes * 60_000L);
        return t;
    }

    private boolean checkToken(String token) {
        if (token == null || token.isEmpty()) return false;
        Long exp = sessions.get(token);
        if (exp == null) return false;
        if (System.currentTimeMillis() > exp) {
            sessions.remove(token);
            return false;
        }
        return true;
    }

    private String issueNonce() {
        String n = randomHex(16);
        nonces.put(n, System.currentTimeMillis() + 120_000L);
        return n;
    }

    private boolean consumeNonce(String n) {
        Long exp = nonces.remove(n);
        return exp != null && System.currentTimeMillis() <= exp;
    }

    private long gateWait(String ip) {
        Gate g = gates.get(ip);
        if (g == null) return 0;
        long now = System.currentTimeMillis();
        if (g.lockedUntil > now) return Math.max(1, (g.lockedUntil - now) / 1000);
        return 0;
    }

    private long gateFail(String ip) {
        long now = System.currentTimeMillis();
        Gate g = gates.computeIfAbsent(ip, k -> new Gate());
        synchronized (g) {
            if (g.lockedUntil > now) return Math.max(1, (g.lockedUntil - now) / 1000);
            if (now - g.windowStart > 600_000L) { g.fails = 0; g.windowStart = now; }
            g.fails++;
            if (g.fails >= loginMaxFails) {
                g.lockedUntil = now + loginLockSeconds * 1000L;
                g.fails = 0;
                return loginLockSeconds;
            }
        }
        return 0;
    }

    /* ============================== HTTP 工具 ============================== */

    private void sendResource(HttpExchange ex, String resPath, String contentType) throws IOException {
        InputStream in = plugin.getClass().getClassLoader().getResourceAsStream(resPath);
        if (in == null) {
            sendJson(ex, 404, "{\"error\":\"not found\"}");
            return;
        }
        byte[] data;
        try (InputStream is = in; ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) > 0) bos.write(buf, 0, n);
            data = bos.toByteArray();
        }
        applySecurity(ex.getResponseHeaders());
        ex.getResponseHeaders().set("Content-Type", contentType);
        ex.sendResponseHeaders(200, data.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(data); }
    }

    private void sendJson(HttpExchange ex, int code, String json) throws IOException {
        byte[] data = json.getBytes(StandardCharsets.UTF_8);
        applySecurity(ex.getResponseHeaders());
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(code, data.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(data); }
    }

    private void applySecurity(Headers h) {
        h.set("Content-Security-Policy",
                "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
                "connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; " +
                "frame-ancestors 'none'; object-src 'none'");
        h.set("X-Content-Type-Options", "nosniff");
        h.set("X-Frame-Options", "DENY");
        h.set("Referrer-Policy", "no-referrer");
        h.set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()");
        h.set("Cache-Control", "no-store");
    }

    private String readBody(HttpExchange ex) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int total = 0;
        int n;
        InputStream is = ex.getRequestBody();
        while ((n = is.read(buf)) > 0) {
            total += n;
            if (total > 64 * 1024) throw new IOException("请求体过大");
            bos.write(buf, 0, n);
        }
        return bos.toString(StandardCharsets.UTF_8);
    }

    private static String bearer(HttpExchange ex) {
        String h = ex.getRequestHeaders().getFirst("Authorization");
        if (h == null) return null;
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("^Bearer\\s+([A-Za-z0-9_-]+)$", java.util.regex.Pattern.CASE_INSENSITIVE)
                .matcher(h.trim());
        return m.matches() ? m.group(1) : null;
    }

    /* ============================== 密码学 ============================== */

    static String sha256(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder b = new StringBuilder(64);
            for (byte x : d) b.append(String.format("%02x", x));
            return b.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }

    static boolean safeEqual(String a, String b) {
        if (a == null || b == null) return false;
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    static String randomHex(int bytes) {
        byte[] buf = new byte[bytes];
        new java.security.SecureRandom().nextBytes(buf);
        StringBuilder b = new StringBuilder(bytes * 2);
        for (byte x : buf) b.append(String.format("%02x", x));
        return b.toString();
    }
}
