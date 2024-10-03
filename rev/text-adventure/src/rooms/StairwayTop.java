package rooms;

import utility.Player;

public class StairwayTop extends Room {
    private Room stairwayBottom = new StairwayBottom(this);

    public StairwayTop(Room prevRoom) {
        this.previousRoom = prevRoom;
    }

    @Override
    public void enter() {
        if (!Player.instance.hasItem("torch")) {
            darkRoom();
        } else {
            System.out.println("You find yourself at the top of a long stair descending downward. You cannot make out the bottom.");
            System.out.println("Behind you lies the great hall you first entered through.");
            while (true) {
                String input = getInput();
                switch (input.toLowerCase()) {
                    case "descend":
                    case "go down":
                        System.out.println("You muster all of your courage and wander down into the depths...");
                        stairwayBottom.enter();
                        break;
                    case "leave":
                    case "go hall":
                    case "go to the hall":
                    case "go back":
                        System.out.println("You exit back into the hall you came through.");
                        previousRoom.enter();
                        break;
                    default:
                        System.out.println("Can't do that.");
                        break;
                }
            }
        }
    }
}
