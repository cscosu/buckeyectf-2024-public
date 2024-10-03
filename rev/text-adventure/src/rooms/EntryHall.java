package rooms;

import utility.Player;

public class EntryHall extends Room {
    Room spiderHall = new SpiderHallway(this);
    Room stairway = new StairwayTop(this);
    Room bridge = new Bridge(this);

    boolean hasTorch = true;

    public EntryHall(Room previousRoom) {
        this.previousRoom = previousRoom;
    }

    @Override
    public void enter() {
        System.out.print("You find yourself in a central hall.");
        if (hasTorch) {
         System.out.print(" It is faintly lit by a torch on the leftmost wall.");
        }
        System.out.println("\nThrough the gloom you barely make out three arches to ongoing passages: one left, one middle, and one right.");

        while (true) {
            String input = getInput();
            switch (input.toLowerCase()) {
                case "equip torch":
                case "pick up torch":
                case "grab torch":
                case "take torch":
                    if (hasTorch) {
                        Player.instance.equipItem("torch");
                        hasTorch = false;
                    } else {
                        System.out.println("You already picked that up.");
                    }
                    break;
                case "go left":
                    System.out.println("You pass through the left corridor...");
                    spiderHall.enter();
                    break;
                case "go center":
                case "go middle":
                    System.out.println("You pass through the middle corridor...");
                    stairway.enter();
                    break;
                case "go right":
                    System.out.println("You pass through the right corridor...");
                    bridge.enter();
                    break;
                case "go back":
                    System.out.println("You exit back into the light of day beyond the cave.");
                    previousRoom.enter();
                    break;
                default:
                    System.out.println("Can't do that.");
                    break;
            }
        }
    }
}
