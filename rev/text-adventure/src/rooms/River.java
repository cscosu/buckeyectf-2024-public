package rooms;

import utility.Player;

public class River extends Room {
    private Room acrossRiver = new AcrossRiver(this);

    public River(Room prevRoom) {
        this.previousRoom = prevRoom;
    }

    @Override
    public void enter() {
        System.out.println("You find yourself alongside a great rushing underground river!\n"
        + "The remains of a broken bridge lie torn and rotted. You'll have to find some other way to cross.\n"
        + "There's a great root of some tree sticking out from the ceiling, but it's too high for you to reach.\n"
        + "The base of the steps lie behind you.");
        while (true) {
            String input = getInput();
            switch (input.toLowerCase()) {
                case "swing across":
                case "swing":
                case "throw rope":
                case "throw the rope":
                case "use rope":
                case "use the rope":
                    if (Player.instance.hasItem("rope")) {
                        System.out.println("You throw with all your might, and the rope catches on the root! You swing across safely.");
                        acrossRiver.enter();
                    } else {
                        System.out.println("Hmm, that root might hold your weight... if only you had some rope.");
                    }
                    break;
                case "swim":
                case "dive":
                    System.out.println("The water's moving too fast for you to swim across.");
                    break;
                case "jump":
                    System.out.println("Too far to jump.");
                    break;
                case "leave":
                case "go steps":
                case "go to the steps":
                case "go back":
                    System.out.println("You return to the base of the steps.");
                    previousRoom.enter();
                    break;
                default:
                    System.out.println("Can't do that.");
                    break;
            }
        }
    }
}
