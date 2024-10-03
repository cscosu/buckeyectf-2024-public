package utility;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.FileReader;

public class MagicOrb {
    public void printFlag() throws IOException {
        BufferedReader br = new BufferedReader(new FileReader("/flag"));
        String line;
        while ((line = br.readLine()) != null) {
            System.out.println(line);
        }
        br.close();
    }
}
