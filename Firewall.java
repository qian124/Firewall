import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;

public class Firewall {

    private Map<Integer, List<long[]>> inTCP;
    private Map<Integer, List<long[]>> outTCP;
    private Map<Integer, List<long[]>> inUDP;
    private Map<Integer, List<long[]>> outUDP;

    public Firewall(String path) throws IOException {
        inTCP = new HashMap<>();
        outTCP = new HashMap<>();
        inUDP = new HashMap<>();
        outUDP = new HashMap<>();
        buildRules(path);
    }

    private void buildRules(String path) throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(path));
        String next = br.readLine();
        while(next!=null) {
            insertRule(next);
            next = br.readLine();
        }
        sortIPRange(inTCP);
        sortIPRange(outTCP);
        sortIPRange(inUDP);
        sortIPRange(outUDP);
        br.close();
    }

    private void insertRule(String s) {
        String[] rule = s.split(",");
        long[] ip = parseIPRange(rule[3]);
        int[] port = parsePortRange(rule[2]);
        boolean in = rule[0].equals("inbound");
        boolean tcp = rule[1].equals("tcp");

        if(in) {
            if(tcp) insertToMap(inTCP, ip, port);
            else insertToMap(inUDP, ip, port);
        }
        else{
            if(tcp) insertToMap(outTCP, ip, port);
            else insertToMap(outUDP, ip, port);
        }
    }

    private int[] parsePortRange(String s) {
        int leftPort = 0, rightPort = 0;
        if(s.contains("-")){
            String[] ports = s.split("-");
            leftPort = Integer.parseInt(ports[0]);
            rightPort = Integer.parseInt(ports[1]);
        }
        else {
            leftPort = Integer.parseInt(s);
            rightPort = leftPort;
        }
        return new int[]{leftPort, rightPort};
    }

    private long[] parseIPRange(String s) {
        long leftIP = 0L, rightIP = 0L;
        if(s.contains("-")){
            String[] IPs = s.split("-");
            leftIP = ipToLong(IPs[0]);
            rightIP = ipToLong(IPs[1]);
        }
        else {
            leftIP = ipToLong(s);
            rightIP = leftIP;
        }
        return new long[]{leftIP, rightIP};
    }

    private long ipToLong(String s) {
        String[] nums = s.split("\\.");
        long re = 0L;
        for(String num : nums) {
            int curr = Integer.parseInt(num);
            re *= 256;
            re += curr;
        }
        return re;
    }

    private void insertToMap(Map<Integer, List<long[]>> map, long[] ip, int[] port) {
        int leftPort = port[0], rightPort = port[1];
        long leftIp = ip[0], rightIp = ip[1];
        if(leftPort == rightPort) {
            map.putIfAbsent(leftPort, new ArrayList<>());
            map.get(leftPort).add(ip);
        }
        else {
            for(int p=leftPort; p<=rightPort; p++) {
                map.putIfAbsent(p, new ArrayList<>());
                map.get(p).add(ip);
            }
        }
    }

    private void sortIPRange(Map<Integer, List<long[]>> map) {
        if(map.isEmpty()) return;
        for(int i : map.keySet()){
            List<long[]>ipRange = map.get(i);
            Collections.sort(ipRange, (a, b)-> {
                return Long.compare(a[0], b[0]);
            });
        }
    }

    public boolean accept_packet(String direction, String protocol, Integer port, String ip) {
        boolean in = direction.equals("inbound");
        boolean tcp = protocol.equals("tcp");
        long IP = ipToLong(ip);

        if(in) {
            if(tcp) return verify(inTCP, IP, port);
            else return verify(inUDP, IP, port);
        }
        else {
            if(tcp) return verify(outTCP, IP, port);
            else return verify(outUDP, IP, port);
        }
    }

    private boolean verify(Map<Integer, List<long[]>> map, long ip, int port) {
        if(map.isEmpty() || !map.containsKey(port)) return false;
        List<long[]> ipRange = map.get(port);
        if(ipRange.get(0)[0]>ip) return false;

        int left = 0, right = ipRange.size()-1, mid = 0;
        while(left <= right) {
            mid = left + (right-left)/2;
            long midIP = ipRange.get(mid)[0];
            if(midIP == ip) return true;
            else if (midIP > ip) right = mid-1;
            else left = mid+1;
        }

        for(int i = left-1; i>=0; i--) {
            long[] range = ipRange.get(i);
            if(range[0]==ip || range[1]>=ip) return true;
        }
        return false;
    }

}
