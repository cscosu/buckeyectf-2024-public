import random


#read in the flag
flag = open("flag.txt", "r")

#--------------------------HELPER FUNCTIONS-----------------------------


#moves donut from the current stack (s_curr), to the new stack (s_new)
def move_donut(s_curr, s_new):
    if s_curr:
        d_curr = s_curr.pop()
    else:
        print("No donuts on that stack")
        return
    #if the new stack has a donut on it already
    if(len(s_new)>0):
        d_new = s_new.pop()
        #if the current donut is smaller than the new donut on the new stack
        if(d_curr<d_new):
            s_new.append(d_new)
            s_new.append(d_curr)
        #else trying to put a bigger donut onto a smaller donut, reset the stacks
        else:
            print('Your donut is too big for this stack')
            s_curr.append(d_curr)
            s_new.append(d_new)
    #if no donut on new stack, then add d_curr donut
    else:
        s_new.append(d_curr)


#takes a stack and prints out the stack with the donuts on it
def print_donut(s):
    print(" "*max + "|")
    if(len(s)>0):
        d = s.pop()
        print((max-d)*" " + ("-"*d) + "|" + ("-"*d) )
        print_donut(s)
        s.append(d)




#prints all three stacks with all their donuts
def print_stacks(s1, s2, s3):
    print_donut(s1)
    print("\n" +" "*max + "|")
    print_donut(s2)
    print("\n" +" "*max + "|")
    print_donut(s3)
    print()



#-------------------Initializing variables below--------------


stack1 = []
stack2 = []
stack3 = []

#a win stack to check to see if the user has won
win= []

#number of donuts +1
max = 11


#add starter donuts to random stacks
for i in range(1,max):
    temp_r = random.randrange(0,3)
    if(temp_r==0):
        stack1.append(max-i)
    elif(temp_r==1):
        stack2.append(max-i)
    else:
        stack3.append(max-i)

    win.append(max-i)



#----------------------GAME LOOP BELOW-------------------------

#while the user has not won the game
while(stack3!=win):
    print_stacks(stack1, stack2, stack3)

    #get first stack
    s_in1 = input("Enter the stack number you would like to move a donut from (1, 2 or 3):\n").strip()

    if(s_in1=="1"):
        s_curr = stack1
    elif(s_in1=="2"):
        s_curr=stack2
    elif(s_in1=="3"):
        s_curr=stack3
    else:
        print("Invalid ring")
        continue

    #get second stack
    s_in2 = input("Enter the stack number you would like to move this donut to (1, 2 or 3):\n").strip()

    if(s_in2=="1"):
        s_new = stack1
    elif(s_in2=="2"):
        s_new=stack2
    elif(s_in2=="3"):
        s_new=stack3
    else:
        print("Invalid ring")
        continue

    #move the top donut of current stack (s_curr) to the top of the new stack (s_new)
    move_donut(s_curr, s_new)

#when user's stack 3 = win stack, the user has won
print(flag.read())
