#!/bin/sh

uglifyjs --screw-ie8 -mco gumscript-runtime.js gumscript-runtime-core.js gumscript-runtime-objc.js gumscript-runtime-dalvik.js
python3 js2c.py < gumscript-runtime.js > gumscript-runtime.h
rm gumscript-runtime.js
