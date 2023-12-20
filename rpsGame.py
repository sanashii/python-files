import random

list = ["ROCK", "PAPER", "SCISSORS"]

def scorePrinter(px, py):
    print("PLAYER 1 SCORE: ", px)
    print("OPPONENT: ", py)
    if(px > py):
        print("PLAYER 1 WINS!")
    elif(px == py):
        print("IT'S A TIE!")
    else:
        print("PLAYER 2/BOT WINS!")

def botPlay(rounds):
    ctr = 1
    ploop = 0
    mum = 0
    tie = 0
    while(ctr <= rounds):
        p1 = input("Player 1: ")
        urmom = print("Bot: ", random.choice(list))
        if(p1 == urmom):
            tie += 1
        elif(p1 == "ROCK"):
            if(urmom == "PAPER"):
                mum += 1
            elif( urmom == "SCISSORS"):
                ploop += 1
        elif(p1 == "PAPER"):
            if(urmom == "SCISSORS"):
                mum += 1
            elif(urmom == "ROCK"):
                ploop += 1
        elif(p1 == "SCISSORS"):
            if(urmom == "ROCK"):
                mum += 1
            elif(urmom == "PAPER"):
                ploop += 1
        if(ctr == rounds):
            print("=======================")
            scorePrinter(ploop, mum)
        ctr += 1

print("Hello! So you're here to play Rock, Paper, Scissors huh?")
print("Aight bet, choose your mode:")
print("1. P1 vs AI")
print("2. P1 vs P2 (you'll need a friend though)")
print("3. P1 vs P1's Inner Demons (IMPOSSIBLE!!!)")
mode = int(input("So, what will it be? [1, 2, 3]: ")) #pls dont forget to type cast otherwise itll be treated as a string always
rounds = int(input("Hm okay, how many rounds do you want?: "))
print("DON'T FORGET TO TYPE UR ANSWER IN CAPS OR DEATH\n\n")
if(mode == 1):
    botPlay(rounds)
