REALLY_BIG_NUMBER = 100000
import os

class Logger(object):
    """docstring for Logger"""
    def __init__(self, idx=0):
        self.idx = idx
        self.create_log()
        
    def create_log(self):
        if not os.path.exists(f"logs/"):
            os.mkdir(f"logs")
        if not os.path.exists(f"logs/{self.idx}"):
            os.mkdir(f"logs/{self.idx}")
        self.clear_log()
        self.clear_trace_log()
        self.clear_msg_log()
        self.clear_watchdog_log()

    def update_log(self):
        self.idx += 1
        self.create_log()

    def clear_log(self):
        open(f'logs/{self.idx}/strat.log', 'w+').close()

    def log(self, s):
        with open(f'logs/{self.idx}/strat.log', 'a+') as f:
            f.write(s + "\n")

    def clear_explorer_log(self):
        open('logs/explorer.log', 'w+').close()

    def explorer_log(self, s):
        with open('logs/explorer.log', 'a+') as f:
            f.write(s + "\n")

    def clear_trace_log(self):
        open(f'logs/{self.idx}/trace.log', 'w+').close()

    def trace_log(self, s):
        with open(f'logs/{self.idx}/trace.log', 'a+') as f:
            f.write(s + "\n")

    def clear_msg_log(self):
        open(f'logs/{self.idx}/message.log', 'w+').close()

    def log_msg(self, s):
        with open(f'logs/{self.idx}/message.log', 'a+') as f:
            f.write(s + "\n")

    def clear_watchdog_log(self):
        open(f'logs/{self.idx}/watchdog.log', 'w+').close()

    def log_watchdog(self, s):
        with open(f'logs/{self.idx}/watchdog.log', 'a+') as f:
            f.write(s + "\n")

def loc_key_str(loc_key):
    pc, callstack = loc_key
    return (hex(pc) + " : " + str([hex(addr) for addr in callstack]))



logger = Logger()
