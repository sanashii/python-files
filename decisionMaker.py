from cProfile import label
import random
from turtle import goto
import numpy as np

def yesOrYes():
    sana = random.randint(0, 72)
    if(sana % 2 == 0):
        return "YES"
    else:
        return "NO"

def numboor(n):
    return(random.randint(0, n))

def crisis(n):
    list = [n]
    print("Damn, ok.. Enumerate your stuff pls.. ⚆_⚆")
    for x in range(0, n):
        string = input((x+1))
        list.append(string)
    chooser = numboor(n)
    ans = list[chooser]
    return ans

ajinomoto = 0
while(ajinomoto != 1):
    print("\nWELCOME, YOU INDECISIVE FREAK!! ψ(｀∇´)ψ\n")
    print("1. Yes or No Generator")
    print("2. Random Number Generator")
    print("3. Your own life crisis")
    ans = int(input("\nPlease pick a service from our decision menu or death: "))
    if(ans == 1):
        print("\nIt's a", yesOrYes())
    elif(ans == 2):
        n = int(input("\nEnter your desired range for this thing: "))
        print("Here's your number:", numboor(n))
    elif(ans == 3):
        n = int(input("\nHow many crisis are you dealing with right now?: "))
        print("Alright, heres's my answer to that:", crisis(n))
    ehe = input("Are you still problematic & indecisive? [Y/N]: ")
    if(ehe == 'N' or ehe == 'n'):
        ajinomoto += 1
print("Ok bye then.")