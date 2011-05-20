#!/bin/sh

coffee -cb gumscript-runtime.coffee 
python js2c.py < gumscript-runtime.js > gumscript-runtime.h
rm gumscript-runtime.js
