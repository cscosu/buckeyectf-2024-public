package rooms;

public class StairwayBottom extends Room {
    private Room sealedDoor = new SealedDoor(this);
    private Room river = new River(this);

    public StairwayBottom(Room prevRoom) {
        this.previousRoom = prevRoom;
    }

    @Override
    public void enter() {
        System.out.println("You are at the base of the stairway. Two paths lay before you, one left and one right.\n" +
            "You hear the sound of rushing water coming from the right passageway.");
        while (true) {
            String input = getInput();
            switch (input.toLowerCase()) {
                case "go left":
                case "left":
                    System.out.println("You head into the left passageway...");
                    sealedDoor.enter();
                    break;
                case "go right":
                case "right":
                    System.out.println("You head into the right passageway...");
                    river.enter();
                    break;
                case "ascend":
                case "go up":
                case "up stairs":
                case "leave":
                case "go back":
                    System.out.println("You go up the steps...");
                    previousRoom.enter();
                    break;
                default:
                    System.out.println("Can't do that.");
                    break;
            }
        }
    }
}
