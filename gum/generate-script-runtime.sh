#!/bin/sh

uglifyjs2 -mco gumscript-runtime.js gumscript-runtime-core.js gumscript-runtime-objc.js
python js2c.py < gumscript-runtime.js > gumscript-runtime.h
rm gumscript-runtime.js
