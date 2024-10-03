package rooms;

import java.util.Scanner;

public abstract class Room {
    static Scanner scan = new Scanner(System.in);

    protected Room previousRoom;

    public abstract void enter();

    protected static String getInput() {
        System.out.print("\n> ");
        String in = scan.nextLine();
        System.out.print("\n");


        if (in.equals("exit")) {
            System.out.println("Okay, goodbye!");
            scan.close();
            System.exit(0);
        }

        return in;
    }

    protected void darkRoom() {
        System.out.println("It's too dark to see anything!");
        while (true) {
            String input = getInput();
            switch (input.toLowerCase()) {
                case "leave":
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
