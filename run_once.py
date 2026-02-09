import os
from app.run_once import run

if __name__ == "__main__":
    trigger = os.environ.get("RUN_TRIGGER", "manual")
    run(trigger=trigger)
