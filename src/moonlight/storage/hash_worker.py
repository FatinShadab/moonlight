"""Use the bounded hash protocol with no-follow storage file opens."""

from moonlight.collectors.hash_worker import main
from moonlight.storage.filesystem import LocalFileSystem

if __name__ == "__main__":
    raise SystemExit(main(open_file=LocalFileSystem().open_file))
