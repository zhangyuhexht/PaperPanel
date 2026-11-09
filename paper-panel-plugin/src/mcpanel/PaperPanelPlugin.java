package mcpanel;

import org.bukkit.Bukkit;
import org.bukkit.plugin.java.JavaPlugin;

import com.sun.management.OperatingSystemMXBean;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.util.ArrayList;
import java.util.List;

/**
 * PaperPanel —— 服务器网页后台控制台插件。
 * 开服自带网页面板：控制台输出 / 指令下发 / TPS / 在线人数 / 主机 CPU。
 */
public final class PaperPanelPlugin extends JavaPlugin {

    private ConsoleCapture capture;
    private PanelHttpServer http;
    private volatile StatsSnapshot stats;
    private final List<Double> tpsHist = new ArrayList<>();

    private String host;
    private int port;
    private int sessionTtlMinutes;
    private int loginMaxFails;
    private int loginLockSeconds;
    private String password;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        host = getConfig().getString("host", "0.0.0.0");
        port = getConfig().getInt("port", 52369);
        password = getConfig().getString("password", "change-me-123");
        sessionTtlMinutes = getConfig().getInt("session-ttl-minutes", 480);
        loginMaxFails = getConfig().getInt("login-max-fails", 8);
        loginLockSeconds = getConfig().getInt("login-lock-seconds", 300);
        int backlog = getConfig().getInt("log-backlog-lines", 80);
        int bufferMax = getConfig().getInt("log-buffer-max", 800);

        capture = new ConsoleCapture();
        capture.setMax(bufferMax);
        capture.attach();

        updateStats();
        http = new PanelHttpServer(this, capture, password, sessionTtlMinutes, loginMaxFails, loginLockSeconds, backlog);
        try {
            http.start(host, port);
        } catch (IOException e) {
            getLogger().severe("网页后台启动失败（端口 " + port + "）: " + e.getMessage());
            capture.detach();
            Bukkit.getPluginManager().disablePlugin(this);
            return;
        }

        capture.push("INFO", "[PaperPanel] 网页后台已启动 -> 端口 " + port + "（面板密码在 plugins/PaperPanel/config.yml）");
        getLogger().info("网页后台已启动，端口 " + port);

        // 每秒刷新一次指标缓存；每 3 秒向 SSE 广播一次
        Bukkit.getScheduler().runTaskTimer(this, this::tick, 20L, 20L);
    }

    @Override
    public void onDisable() {
        if (http != null) http.stop();
        if (capture != null) capture.detach();
    }

    private void tick() {
        updateStats();
        if (http != null) http.broadcastStats(getStats().toJson());
    }

    private void updateStats() {
        double[] tps = Bukkit.getTPS();
        if (tps == null || tps.length == 0) tps = new double[]{20.0, 20.0, 20.0};
        double t1 = tps[0];
        synchronized (tpsHist) {
            tpsHist.add(t1);
            while (tpsHist.size() > 40) tpsHist.remove(0);
        }
        List<Double> histCopy;
        synchronized (tpsHist) { histCopy = new ArrayList<>(tpsHist); }

        List<String> names = new ArrayList<>();
        for (org.bukkit.entity.Player p : Bukkit.getOnlinePlayers()) names.add(p.getName());

        Runtime rt = Runtime.getRuntime();
        long memUsed = rt.totalMemory() - rt.freeMemory();
        long memTotal = rt.maxMemory();

        double cpu = 0.0;
        java.lang.management.OperatingSystemMXBean bean = ManagementFactory.getOperatingSystemMXBean();
        if (bean instanceof OperatingSystemMXBean) {
            OperatingSystemMXBean os = (OperatingSystemMXBean) bean;
            double load = os.getCpuLoad();
            if (load < 0) load = 0.0;
            cpu = Math.min(100.0, load * 100.0);
        }

        stats = new StatsSnapshot(
                new double[]{tps[0], tps.length > 1 ? tps[1] : tps[0], tps.length > 2 ? tps[2] : tps[0]},
                names.size(),
                Bukkit.getMaxPlayers(),
                names.toArray(new String[0]),
                cpu,
                memUsed,
                memTotal,
                histCopy
        );
    }

    public StatsSnapshot getStats() {
        StatsSnapshot s = stats;
        if (s == null) updateStats();
        return stats;
    }

    public ConsoleCapture getCapture() { return capture; }
}
