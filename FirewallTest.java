import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import static org.junit.Assert.assertTrue;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;


public class FirewallTest {

    public  static  String PATH = "fw.csv";

//    @Before
//    public  void setup() throws IOException {
//        BufferedWriter bwr = new BufferedWriter(new FileWriter(""fw.csv"));
//        for(int i=0; i<=1000; i++) {
//            bwr.write("outbound,tcp,1-65535,0.0.0.1-255.255.255.255");
//            bwr.newLine();
//        }
//        bwr.close();
//    }

    @Test
    public void test() throws IOException {

        Firewall fw = new Firewall(PATH);
        assertTrue(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2")) ;
        assertTrue(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11"));
        assertTrue(fw.accept_packet("inbound", "udp", 53, "192.168.2.1"));
        assertFalse(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"));
        assertFalse(fw.accept_packet("inbound", "tcp", 999, "52.12.48.1"));
        assertTrue(fw.accept_packet("outbound", "tcp", 59999, "192.171.10.11"));
        assertTrue(fw.accept_packet("outbound", "udp", 1, "0.0.0.1"));
        assertTrue(fw.accept_packet("outbound", "udp", 65535, "255.255.255.255"));
    }
}


