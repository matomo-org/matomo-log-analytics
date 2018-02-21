#!/bin/sh

cd $(dirname $0)

# Make sure nosetests is installed.
pytest --version  >/dev/null 2>&1 || (echo "nose (http://readthedocs.org/docs/nose/en/latest/) must be installed"; exit 1)

PYTHONPATH=.. pytest $*
