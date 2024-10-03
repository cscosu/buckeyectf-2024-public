package rooms;

public class CaveEnterance extends Room {
    Room entryHall = new EntryHall(this);

    @Override
    public void enter() {
        System.out.println("You find yourself standing at the opening of a vast, mysterious cave. The entrance looms before you, awaiting.");

        while (true) {
            String input = getInput();
            switch (input.toLowerCase()) {
                case "enter":
                case "go in":
                    System.out.println("You feel the air grow cool as you pass through the threshold into the depths...");
                    entryHall.enter();
                    break;
                case "leave":
                case "go back":
                    System.out.println("Go back? GO BACK? You cannot go back. Your fate is fixed; you have no choice.");
                    break;
                default:
                    System.out.println("Can't do that.");
                    break;
            }
        }
    }
}
