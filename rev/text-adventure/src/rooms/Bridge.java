package rooms;

import utility.Player;

public class Bridge extends Room {
    private Room crystalRoom = new CrystalRoom(this);

    public Bridge(Room prevRoom) {
        this.previousRoom = prevRoom;
    }

    @Override
    public void enter() {
        if (!Player.instance.hasItem("torch")) {
            darkRoom();
        } else {
            System.out.println("You find yourself standing at the edge of an unfathomable chasm! Far off, you can hear fast running water below.\n"
            +"There lies a stone bridge spanning the gap, but it's little more than a few feet wide. It arches away from you, and disappears into the darkness.\n"
            +"The main hall lies behind you.");
            while (true) {
                String input = getInput();
                switch (input.toLowerCase()) {
                    case "go across":
                    case "cross":
                    case "cross the bridge":
                    case "walk across":
                        System.out.println("You slowly edge out on to the bridge... holding your breath...");
                        System.out.println("...and eventually make it to the other side. Uh, good job.");
                        crystalRoom.enter();
                        break;
                    case "jump":
                    case "jump off":
                        System.out.println("You wouldn't survive a fall from this height.");
                        break;
                    case "use rope":
                    case "rope":
                        System.out.println("The rope isn't long enough to get you to the bottom of the chasm.");
                        break;
                    case "leave":
                    case "go back":
                    case "go hall":
                    case "go to the hall":
                        System.out.println("You return to the hall you entered through.");
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
