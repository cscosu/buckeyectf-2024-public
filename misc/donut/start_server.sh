#!/bin/sh

socat tcp-l:5000,reuseaddr,fork SYSTEM:"python3 donuts.py",stderr