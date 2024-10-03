package rooms;

import utility.Player;

public class SealedDoor extends Room {
    private Room deadEnd = new DeadEnd(this);

    private boolean locked = true;

    public SealedDoor(Room prevRoom) {
        this.previousRoom = prevRoom;
    }

    @Override
    public void enter() {
        if (locked) {
            lockedRoom();
        } else {
            unlockedRoom();
        }
    }

    private void lockedRoom() {
        if (locked) {
            System.out.println("You enter a small room, with stone close all around you. Before you lies a door sealed with a large lock.\n"
            +"Behind you lie the base of the steps.");
        } else {
            System.out.println("You return to the small room, with stone close all around you. Before you lies a great door, but it's unlocked now.\n"
            +"Behind you lie the base of the steps.");
        }
        while (true) {
            String input = getInput();
            switch (input.toLowerCase()) {
                case "open door":
                case "open the door":
                    System.out.println("It's, uh, locked.");
                    break;
                case "unlock":
                case "unlock door":
                case "unlock the door":
                    if (Player.instance.hasItem("key")) {
                        System.out.println("You fit the key into the lock, and slowly start to turn it...");
                        System.out.println("It works! The lock falls away and you pass through the door.");
                        locked = false;
                        deadEnd.enter();
                    } else {
                        System.out.println("Looks like you'll have to find a key.");
                    }
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

    private void unlockedRoom() {
        System.out.println("You enter a small room with stone close all around. Before you lies the door you unlocked.");
        while (true) {
            String input = getInput();
            switch (input.toLowerCase()) {
                case "enter":
                case "go through":
                    System.out.println("You enter back through the door...");
                    deadEnd.enter();
                case "leave":
                case "go back":
                    System.out.println("You return back to the base of the steps.");
                    previousRoom.enter();
                    break;
                default:
                    System.out.println("Can't do that.");
                    break;
            }
        }
    }
}
