package mcpanel;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Deque;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * 控制台捕获：挂到 log4j root logger 上，把服务器全部控制台输出
 * 收进环形缓冲，并推给已连接的 SSE 监听器。
 */
public final class ConsoleCapture extends AbstractAppender {

    public static final class Entry {
        public final int seq;
        public final String t;
        public final String level;
        public final String text;

        Entry(int seq, String t, String level, String text) {
            this.seq = seq;
            this.t = t;
            this.level = level;
            this.text = text;
        }

        public String toJson() {
            return "{\"seq\":" + seq
                    + ",\"t\":\"" + JsonUtil.esc(t) + "\""
                    + ",\"level\":\"" + JsonUtil.esc(level) + "\""
                    + ",\"text\":\"" + JsonUtil.esc(text) + "\"}";
        }
    }

    private final Deque<Entry> ring = new LinkedList<>();
    private final List<Consumer<Entry>> listeners = new CopyOnWriteArrayList<>();
    private final SimpleDateFormat fmt = new SimpleDateFormat("HH:mm:ss");
    private int seq = 0;
    private int max = 800;

    public ConsoleCapture() {
        super("PaperPanelCapture", null, null, true, Property.EMPTY_ARRAY);
    }

    public void setMax(int max) {
        this.max = Math.max(50, max);
    }

    public void attach() {
        start();
        ((Logger) LogManager.getRootLogger()).addAppender(this);
    }

    public void detach() {
        ((Logger) LogManager.getRootLogger()).removeAppender(this);
        stop();
    }

    @Override
    public void append(LogEvent event) {
        String level = mapLevel(event.getLevel().name());
        String text = event.getMessage() != null ? event.getMessage().getFormattedMessage() : "";
        if (event.getThrown() != null) {
            text = text.isEmpty()
                    ? event.getThrown().toString()
                    : text + " | " + event.getThrown().toString();
        }
        push(level, text);
    }

    /** 手动推一行（如插件自身的状态提示）。 */
    public void push(String level, String text) {
        if (text == null) return;
        // 清除 ANSI 颜色码，避免在网页上显示乱码
        String line = text.replace("\r", "").replaceAll("\\u001B\\[[;\\d]*m", "");
        if (line.trim().isEmpty()) return;
        Entry e;
        synchronized (ring) {
            e = new Entry(++seq, now(), level, line);
            ring.addLast(e);
            while (ring.size() > max) ring.removeFirst();
        }
        for (Consumer<Entry> l : listeners) {
            try { l.accept(e); } catch (Throwable ignored) {}
        }
    }

    public List<Entry> backlog(int n) {
        synchronized (ring) {
            List<Entry> all = new ArrayList<>(ring);
            int from = Math.max(0, all.size() - n);
            return all.subList(from, all.size());
        }
    }

    public void addListener(Consumer<Entry> l) { listeners.add(l); }

    public void removeListener(Consumer<Entry> l) { listeners.remove(l); }

    private String now() {
        synchronized (fmt) { return fmt.format(new Date()); }
    }

    private static String mapLevel(String log4jLevel) {
        if (log4jLevel == null) return "OTHER";
        switch (log4jLevel) {
            case "ERROR":
            case "FATAL":
                return "ERROR";
            case "WARN":
                return "WARN";
            case "INFO":
                return "INFO";
            default:
                return "OTHER";
        }
    }
}
