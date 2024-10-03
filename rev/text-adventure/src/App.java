import rooms.CaveEnterance;
import rooms.Room;

public class App {
    static Room caveEnterance = new CaveEnterance();
    public static void main(String[] args) throws Exception {
        System.out.println("You've been transported to a faraway magical land! Can you find the flag?\n---");
        caveEnterance.enter();
    }
}
