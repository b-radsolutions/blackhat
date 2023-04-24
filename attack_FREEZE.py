
import utils.client as c
import random

def freeze_account(name):
    print(f"Freezing {name}...")
    # Re-create the session
    cli = c.client()
    cli.init()
    # Freeze the account!
    cli.freeze_account(name)

if __name__ == "__main__":
    # Freeze some known accounts
    names = ["Bradley", "Kai"]
    for name in names: freeze_account(name)

    # Let's also screw over some random people
    ATTEMPTS = 100
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    _caps = list(alphabet)
    _lower = list(alphabet.lower())

    # Create random 4-6 letter names
    for _ in range(ATTEMPTS):
        # Pick a random capital letter
        cap = random.choice(_caps)
        # Pick 3-5 random lowercase letters
        length = random.randint(3,5)
        lowercase = random.choices(_lower, k=length)
        name = "".join(list(cap) + lowercase)
        freeze_account(name)
