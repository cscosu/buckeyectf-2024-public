package rooms;

import utility.Player;

public class SpiderHallway extends Room {
    Room keyRoom = new KeyRoom(this);

    private boolean websCut = false;

    public SpiderHallway(Room prevRoom) {
        this.previousRoom = prevRoom;
    }

    public void enter() {
        if (!Player.instance.hasItem("torch")) {
            darkRoom();
        } else {
            if (!websCut) {
                System.out.println("You come upon a long hallway, the walls covered by thick webs. Thousands of little legs seem to scurry away from your torch's light.\n" +
                "You notice a door at the end of the hall, completely covered in webs. You'll need someting sharp to get cut through it.");
            } else {
                System.out.println("You return to the long hall, still covered in webs. The door is free, now, though. You feel like hundreds of tiny eyes are watching your every move.\n" +
                "The main hall lies behind you.");
            }
            while (true) {
                String input = getInput();
                switch (input.toLowerCase()) {
                    case "cut":
                    case "cut through":
                    case "cut the webs":
                    case "cut webs":
                    case "cut the door":
                    case "cut door":
                        if (!websCut) {
                            if (Player.instance.hasItem("sword")) {
                                System.out.println("The sword slices right through the webs! You're able to cut away the door and get through.");
                                websCut = true;
                                keyRoom.enter();
                            } else {
                                System.out.println("With what, your hands?");
                            }
                        } else {
                            System.out.println("You already did that.");
                        }
                        break;
                    case "burn it":
                    case "burn webs":
                    case "burn the webs":
                        System.out.println("You can't seem to get them to light. Must be some kind of magic...");
                        break;
                    case "leave":
                    case "go back":
                    case "go hall":
                    case "go to the hall":
                        System.out.println("You exit back into the hall you first entered in.");
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
