package utility;
import java.util.Set;
import java.util.HashSet;

public class Player {
    public static Player instance = new Player();

    // singleton
    private Player() {
        Inventory = new HashSet<String>();
    }

    private static Set<String> Inventory;

    public void equipItem(String item) {
        if (Inventory.contains(item)) {
            System.out.println("Already have one of those!");
        } else {
            System.out.println("You picked up the " + item + ".");
            Inventory.add(item);
        }
    }

    public boolean hasItem(String item) {
        return Inventory.contains(item);
    }
}
