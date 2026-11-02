"""Research worker process for Docker."""
import time
import defense
import research


def main() -> None:
    defense.migrate()
    while True:
        if not research.work_once():
            time.sleep(2)


if __name__ == '__main__':
    main()
