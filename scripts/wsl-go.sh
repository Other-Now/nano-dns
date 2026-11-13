#!/usr/bin/env bash
# Helper for development on Windows: run a go command inside WSL.
export PATH=$HOME/go-sdk/go/bin:$HOME/go/bin:$PATH
cd /mnt/d/self_projects/nano-dns && exec "$@"
