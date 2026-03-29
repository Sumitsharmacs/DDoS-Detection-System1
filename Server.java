import com.sun.net.httpserver.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.file.*;
import java.util.*;

public class Server {

    static Map<String, List<Long>> traffic = new HashMap<>();
    static Set<String> blocked = new HashSet<>();

    static int totalRequests = 0;
    static boolean globalAttack = false;
    static int logCounter = 0;

    public static void main(String[] args) throws Exception {

        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", 8080), 0);

        server.createContext("/", new MainHandler());
        server.createContext("/admin", new AdminHandler());

        server.start();

        System.out.println("🚀 Server running...");
    }

    static class MainHandler implements HttpHandler {
        public void handle(HttpExchange t) throws IOException {

            // 🔥 MULTI-IP SUPPORT (header based)
            String ip = t.getRequestHeaders().getFirst("X-Forwarded-For");

            if (ip == null) {
                ip = t.getRemoteAddress().getAddress().getHostAddress();
            }

            ip = ip.replace("0:0:0:0:0:0:0:1", "127.0.0.1");

            // 🔥 EARLY BLOCK (NO LOGGING)
            if (blocked.contains(ip)) {
                send(t, "Access Denied", 403);
                return;
            }

            long now = System.currentTimeMillis();

            traffic.putIfAbsent(ip, new ArrayList<>());
            traffic.get(ip).add(now);

            int count = traffic.get(ip).size();

            totalRequests++;

            log("IP: " + ip + " Requests: " + count);

            // 🌍 GLOBAL DETECTION
            if (totalRequests > 100 && !globalAttack) {
                globalAttack = true;
                log("[ALERT] GLOBAL ATTACK DETECTED");
            }

            // 🔥 BURST + HYBRID DETECTION
            if (traffic.get(ip).size() > 5) {

                int size = traffic.get(ip).size();

                long last = traffic.get(ip).get(size - 1);
                long prev = traffic.get(ip).get(size - 5);

                long diff = (last - prev) / 1000;

                if ((count > 30 || diff < 5) && !blocked.contains(ip)) {
                    blocked.add(ip);
                    log("[ALERT] ATTACK DETECTED: " + ip);
                }
            }

            String path = t.getRequestURI().getPath();

            if (path.equals("/style.css")) {
                sendFile(t, "web/style.css");
                return;
            }

            if (path.equals("/script.js")) {
                sendFile(t, "web/script.js");
                return;
            }

            sendFile(t, "web/index.html");
        }
    }

    // 🔥 IMPROVED DASHBOARD
    static class AdminHandler implements HttpHandler {
        public void handle(HttpExchange t) throws IOException {

            String logs;
            try {
                logs = Files.readString(Paths.get("logs/log.txt"));
            } catch (Exception e) {
                logs = "No logs yet";
            }

            int totalIPs = traffic.size();
            int blockedIPs = blocked.size();

            String response = "<html><head><title>Dashboard</title>"
                    + "<style>"
                    + "body{background:#0f172a;color:white;font-family:Arial;text-align:center;}"
                    + ".card{border:2px solid #00ffcc;padding:20px;margin:20px;border-radius:10px;}"
                    + "h1{color:#00ffcc;}"
                    + "</style></head><body>"

                    + "<h1>🚀 DDoS Detection Dashboard</h1>"

                    + "<div class='card'>"
                    + "<h2>Total IPs: " + totalIPs + "</h2>"
                    + "<h2>Blocked IPs: " + blockedIPs + "</h2>"
                    + "<h2>Total Requests: " + totalRequests + "</h2>"
                    + "</div>"

                    + "<div class='card'>"
                    + "<h2>Logs</h2>"
                    + "<pre style='text-align:left;'>" + logs + "</pre>"
                    + "</div>"

                    + "</body></html>";

            send(t, response, 200);
        }
    }

    static void sendFile(HttpExchange t, String file) throws IOException {
        byte[] data = Files.readAllBytes(Paths.get(file));
        t.sendResponseHeaders(200, data.length);
        t.getResponseBody().write(data);
        t.getResponseBody().close();
    }

    static void send(HttpExchange t, String msg, int code) throws IOException {
        byte[] res = msg.getBytes();
        t.sendResponseHeaders(code, res.length);
        t.getResponseBody().write(res);
        t.getResponseBody().close();
    }

    // 🔥 SMART LOGGING
    static void log(String msg) throws IOException {

        if (msg.contains("ALERT")) {
            Files.write(Paths.get("logs/log.txt"), (msg + "\n").getBytes(),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            return;
        }

        logCounter++;

        if (logCounter % 10 != 0) return;

        Files.write(Paths.get("logs/log.txt"), (msg + "\n").getBytes(),
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }
}
