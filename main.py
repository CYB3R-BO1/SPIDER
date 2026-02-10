from core import load_env
from orchestrator.master_agent import MasterAgent

def main():
    load_env()
    master = MasterAgent()
    master.run()

if __name__ == "__main__":
    main()
