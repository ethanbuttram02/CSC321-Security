import random as rand


def submit():
    userid = rand.randint(0, 25565)
    sessionid = rand.randint(0, 25565)

    inputStr = input(str("enter your stuff here: "))
    inputStr = "userid=" + str(userid) + ";userdata=" + inputStr + ";sessionid=" + str(sessionid)

    print(inputStr)

def verify():
    pass

def control():
    submit()

control()