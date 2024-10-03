from pwn import *

#p = process(["python3","donuts.py"] )
p = remote("127.0.0.1", 5000)

final_target = 2

# Solve Towers of Hanoi from arbitrary position
#
# diskPostions -- the current peg for each disk (0, 1, or 2) in decreasing
#                 order of size.  This will be modified
# largestToMove -- move this one and all smaller disks
# targetPeg -- target peg for disks to move
#
def moveDisks(diskPositions, largestToMove, targetPeg):
    for badDisk in range(largestToMove, len(diskPositions)):

        currentPeg = diskPositions[badDisk]         
        if currentPeg != targetPeg:
            #found the largest disk on the wrong peg

            #sum of the peg numbers is 3, so to find the other one...
            otherPeg = 3 - targetPeg - currentPeg

            #before we can move badDisk, we have get the smaller ones out of the way
            moveDisks(diskPositions, badDisk+1, otherPeg)

            p.sendline(str(currentPeg + 1).encode())
            p.sendline(str(targetPeg + 1).encode())
            # msg = p.recvline()
            # if b"Your donut is" in msg:
            #     print("fucled")
            #     exit(-1)
            print(len(list(filter(lambda x: x == 2, diskPositions))))


            diskPositions[badDisk]=targetPeg

            #now we can put the smaller ones in the right place
            moveDisks(diskPositions, badDisk+1, targetPeg)

            break 



stacks = []
num_stacks = 3
num_rings = 10
for stack in range(num_stacks):
    stacks.append(p.recvuntil("\n\n"))

def parse_stack(raw_stack: str) -> list[int]:
    lines = raw_stack.split()
    lines = list(filter(lambda x: len(x) > 1, lines))
    ring_num = [(len(line) - 1) / 2 for line in lines] 

    return ring_num

parsed_stacks = [parse_stack(stack.decode('utf-8')) for stack in stacks]
print(parsed_stacks)

peg_of_ring = [0] * num_rings
for peg, current_rings in enumerate(parsed_stacks):
    for ring in current_rings:
        peg_of_ring[int(ring) - 1] = peg

# Reverse to get "decreasing order of size"
peg_of_ring = peg_of_ring[::-1]

print(f"peg_of_ring: {peg_of_ring}")

moveDisks(peg_of_ring, 0, final_target)
print("Solved??")
p.recvuntil("bctf".encode())
print(p.recvline())
