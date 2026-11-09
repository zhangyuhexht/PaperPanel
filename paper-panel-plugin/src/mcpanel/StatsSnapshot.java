package mcpanel;

import java.util.List;

/** 一次指标快照：TPS / 在线 / CPU / 内存，供 HTTP 层序列化。 */
public final class StatsSnapshot {
    public final double[] tps;
    public final int online;
    public final int max;
    public final String[] names;
    public final double cpu;
    public final long memUsed;
    public final long memTotal;
    public final long ts;
    public final List<Double> tpsHist;

    public StatsSnapshot(double[] tps, int online, int max, String[] names,
                         double cpu, long memUsed, long memTotal, List<Double> tpsHist) {
        this.tps = tps;
        this.online = online;
        this.max = max;
        this.names = names;
        this.cpu = cpu;
        this.memUsed = memUsed;
        this.memTotal = memTotal;
        this.ts = System.currentTimeMillis();
        this.tpsHist = tpsHist;
    }

    public String toJson() {
        StringBuilder b = new StringBuilder(256);
        b.append("{\"tps\":[");
        for (int i = 0; i < 3; i++) {
            if (i > 0) b.append(',');
            b.append(fmt(i < tps.length ? tps[i] : 20.0));
        }
        b.append("],\"tpsHist\":[");
        for (int i = 0; i < tpsHist.size(); i++) {
            if (i > 0) b.append(',');
            b.append(fmt(tpsHist.get(i)));
        }
        b.append("],\"players\":{\"online\":").append(online)
          .append(",\"max\":").append(max)
          .append(",\"names\":[");
        for (int i = 0; i < names.length; i++) {
            if (i > 0) b.append(',');
            b.append('"').append(JsonUtil.esc(names[i])).append('"');
        }
        b.append("]},\"cpu\":").append(fmt(cpu))
          .append(",\"mem\":{\"used\":").append(memUsed)
          .append(",\"total\":").append(memTotal)
          .append("},\"ts\":").append(ts)
          .append(",\"mock\":false}");
        return b.toString();
    }

    private static String fmt(double v) {
        return String.format(java.util.Locale.US, "%.2f", v);
    }
}
