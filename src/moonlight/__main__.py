"""Support python -m moonlight with the same CLI as the installed command."""

from moonlight.cli import main

raise SystemExit(main())
