import utils.client as c
import os
import time


CLIENT = c.client()
CLIENT.init()

print("Who are you? ", end="")
username = input("Username:").strip()
print("Please Verify? ",end="")
password = input("Password:").strip()
account = username.replace('/', '')+"/"+password.replace('/', '')
os.system('cls' if os.name == 'nt' else 'clear')
valid = CLIENT.verify_account(account)
attempts = 0
while attempts > 3 and valid == False:
    print("Please Try Again,",attempts,"Attempts Remain")
    password = input("Password:").strip()
    account = username+"/"+password
    valid = CLIENT.verify_account(account)
if attempts == 0 and valid == False:
    print("You have been locked out of this account, the account has been frozen. The police have been notified")
    CLIENT.freeze_account(username)
    print("Good Day!")
    exit(1)
# initiate challenge

print("Welcome", username)
while True:
    print("What would you like to do today?")
    print("1. Deposit Money")
    print("2. Check Balance")
    print("3. Withdraw Money")
    print("4. Save and Log out of my Account")
    service = input("How are we helping you today?")
    try:
        _ = int(service)
    except:
        os.system('cls' if os.name == 'nt' else 'clear')
        print('Improper service option supplied')
        continue
    if int(service) not in (1,2,3,4):
        print("That response was not recognized")
        continue
    match int(service):
        case 1:
            print("How much money would you like to deposit?")
            try:
                deposit = float(input("USD (truncated to 2 decimals): "))
            except:
                os.system('cls' if os.name == 'nt' else 'clear')
                print('Improper value option supplied')
                continue
            response = CLIENT.deposit_to_account(int(deposit*100))
            # assert deposit+" dollars added to account" == response
            # print(deposit, " dollars have been added to your account")
        case 2:
            balance = CLIENT.check_account_balance()
            print("Your current balance is", float(balance/100.0))
        case 3:
            print("How much money would you like to withdraw?")
            try:
                withdrawal = float(input("USD (truncated to 2 decimals): "))
                withdrawal = int(withdrawal*100) # truncate to two decimals
            except:
                os.system('cls' if os.name == 'nt' else 'clear')
                print('Improper value option supplied')
                continue
            balance = CLIENT.check_account_balance()
            if balance > withdrawal:
                print("Processing your withdrawal now...")
                response = CLIENT.withdraw_from_account(withdrawal)
                # assert withdrawal+" dollars removed from account" == response
                # print(balance - withdrawal, " dollars have been removed from your account")
            else:
                print("You are attempting to withdraw more money than currently exists in your account.")
        case 4:
            CLIENT.exit()
            os.system('cls' if os.name == 'nt' else 'clear')
            print("Thank you for choosing to do business with Conrad International. Have a Nice Day!")
            exit(0)





#The premaster secret: The client sends one more random string of bytes, the "premaster secret." The premaster secret is encrypted with the public key and can only be decrypted with the private key by the server. (The client gets the public key from the server's SSL certificate.)
#Private key used: The server decrypts the premaster secret.
#Session keys created: Both client and server generate session keys from the client random, the server random, and the premaster secret. They should arrive at the same results.
#Client is ready: The client sends a "finished" message that is encrypted with a session key.
#Server is ready: The server sends a "finished" message encrypted with a session key.
#Secure symmetric encryption achieved: The handshake is completed, and communication continues using the session keys.