package rooms;

import utility.Player;

public class AcrossRiver extends Room {

    private boolean hasSword = true;

    public AcrossRiver(Room prevRoom) {
        this.previousRoom = prevRoom;
    }

    @Override
    public void enter() {
        if (hasSword) {
            System.out.println("It looks like there was once a battle here, long ago. You see the remains of a knight, still clothed in armor. A slightly-rusted sword lies across his lap.");
        } else {
            System.out.println("It looks like there was once a battle here, long ago. You still the remains of the knight whose sword you took.");
        }
        while (true) {
            String input = getInput();
            switch (input.toLowerCase()) {
                case "equip sword":
                case "pick up sword":
                case "grab sword":
                case "take sword":
                    if (hasSword) {
                        System.out.println("Seems a shame to leave a fine sword to rust like that... It would be better off with you.");
                        Player.instance.equipItem("sword");
                        hasSword = false;
                    } else {
                        System.out.println("You already did that.");
                    }
                    break;
                case "swim":
                case "dive":
                    System.out.println("The water's moving too fast for you to swim across.");
                    break;
                case "equip armor":
                case "pick up armor":
                case "grab armor":
                case "take armor":
                    System.out.println("You probably won't need that.");
                    break;
                case "leave":
                case "go back":
                case "swing":
                case "swing back":
                case "swing across":
                case "use rope":
                case "use the rope":
                    System.out.println("You throw the rope again, and swing back to the other side.");
                    previousRoom.enter();
                    break;
                default:
                    System.out.println("Can't do that.");
                    break;
            }
        }
    }
}
