package rooms;

import utility.Player;

public class CrystalRoom extends Room {

    private boolean hasRope = true;

    public CrystalRoom(Room prevRoom) {
        this.previousRoom = prevRoom;
    }

    @Override
    public void enter() {
        System.out.println("On the other side of the bridge, you come upon a cavern covered in glistening pink crystals!\n"
        +"Some are so large you can see your reflection in them as they glisten from your torchlight.\n"
        +"Some of the crystals look mined away, but you don't see any sort of pickaxe. All that remains of the mining operation is a bundle of rope.");
        while (true) {
            String input = getInput();
            switch (input.toLowerCase()) {
                case "equip rope":
                case "pick up rope":
                case "grab rope":
                case "take rope":
                    if (hasRope) {
                        Player.instance.equipItem("rope");
                        hasRope = false;
                    } else {
                        System.out.println("You already did that.");
                    }
                    break;
                case "leave":
                case "go back":
                    System.out.println("You brave the bridge once again...");
                    System.out.println("...and again, safely make it across. Surefooted as they come.");
                    previousRoom.enter();
                    break;
                default:
                    System.out.println("Can't do that.");
                    break;
            }
        }
    }
}
