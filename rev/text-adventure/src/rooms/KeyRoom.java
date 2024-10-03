package rooms;

import utility.Player;

public class KeyRoom extends Room {

    private boolean hasKey = true;

    public KeyRoom(Room prevRoom) {
        this.previousRoom = prevRoom;
    }

    @Override
    public void enter() {
        if (hasKey) {
            System.out.println("You come in to a small room with a glowing pedestal in the center.\n"
            +"The light is dazzling, and upon the pedestal lies an ornate key. Neat!");
        } else {
            System.out.println("You come in to a small room with a glowing pedestal in the center.\n"
            +"You already picked up the ornate key, but the light is still beautiful.");
        }
        while (true) {
            String input = getInput();
            switch (input.toLowerCase()) {
                case "equip key":
                case "pick up key":
                case "grab key":
                case "take key":
                    if (hasKey) {
                        System.out.println("You slowly reach out your hand, wary of any traps you might spring, or eyes that might be watching...");
                        System.out.println("...but there aren't any. Easy, right?");
                        Player.instance.equipItem("key");
                        hasKey = false;
                    } else {
                        System.out.println("You already did that.");
                    }
                    break;
                case "leave":
                case "go back":
                    System.out.println("You exit back into the hall of spiders.");
                    previousRoom.enter();
                    break;
                default:
                    System.out.println("Can't do that.");
                    break;
            }
        }
    }

}
