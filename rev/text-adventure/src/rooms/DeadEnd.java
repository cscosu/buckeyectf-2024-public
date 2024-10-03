package rooms;

import utility.MagicOrb;

public class DeadEnd extends Room {
    private MagicOrb flag = new MagicOrb();

    public DeadEnd(Room prevRoom) {
        this.previousRoom = prevRoom;
    }

    @Override
    public void enter() {
        System.out.println("It appears to be a dead end.");
        while (true) {
            String input = getInput();
            switch (input.toLowerCase()) {
                case "leave":
                case "go back":
                    System.out.println("You return back to the room you came through.");
                    previousRoom.enter();
                    break;
                case "reach through the crack in the rocks":
                    System.out.println("What? What crack in the rocks?");
                    input = getInput();
                    if (input.equals("the crack in the rocks concealing the magical orb with the flag")) {
                        System.out.println("There's a crack in the --? Well, it seems you know more about this world than I do. Happy hacking!");
                        try {
                            flag.printFlag();
                        } catch (Exception e) {
                            System.out.println("Hmm.... it seems the magical orb has decided to give you nothing. How strange.");
                        }
                    }
                    break;
                default:
                    System.out.println("Can't do that.");
                    break;
            }
        }
    }
}
