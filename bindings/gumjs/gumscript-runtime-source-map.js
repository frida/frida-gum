/* jshint esnext: true */
(function () {
    "use strict";

    let didLoadSourceMap = false;
    let cachedSourceMap = null;
    Object.defineProperty(Script, 'sourceMap', {
        enumerable: true,
        get: function () {
            if (!didLoadSourceMap) {
                const data = Script._sourceMapData;
                if (data !== null)
                    cachedSourceMap = JSON.parse(data);
                else
                    cachedSourceMap = null;
                didLoadSourceMap = true;
            }
            return cachedSourceMap;
        }
    });

    /*
     * Based on https://github.com/evanw/node-source-map-support
     */

    Error.prepareStackTrace = function (error, stack) {
        return error + stack.map(function (frame) {
            return "\n    at " + wrapCallSite(frame);
        }).join("");
    };

    const sourceMapCache = {};
    function wrapCallSite(frame) {
        // Most call sites will return the source file from getFileName(), but code
        // passed to eval() ending in "//# sourceURL=..." will return the source file
        // from getScriptNameOrSourceURL() instead
        const source = frame.getFileName() || frame.getScriptNameOrSourceURL();
        if (source) {
            const line = frame.getLineNumber();
            const column = frame.getColumnNumber() - 1;

            const position = mapSourcePosition({
                source: source,
                line: line,
                column: column
            });
            frame = cloneCallSite(frame);
            frame.getFileName = function () {
                return position.source;
            };
            frame.getLineNumber = function () {
                return position.line;
            };
            frame.getColumnNumber = function () {
                return position.column + 1;
            };
            frame.getScriptNameOrSourceURL = function () {
                return position.source;
            };
            return frame;
        }

        // Code called using eval() needs special handling
        var origin = frame.isEval() && frame.getEvalOrigin();
        if (origin) {
            origin = mapEvalOrigin(origin);
            frame = cloneCallSite(frame);
            frame.getEvalOrigin = function () {
                return origin;
            };
            return frame;
        }

        // If we get here then we were unable to change the source position
        return frame;
    }

    function mapSourcePosition(position) {
        let item = sourceMapCache[position.source];
        if (!item) {
            const map = findSourceMap(position.source);
            if (map !== null) {
                item = sourceMapCache[position.source] = {
                    map: new SourceMapConsumer(map)
                };
            } else {
                item = sourceMapCache[position.source] = {
                    map: null
                };
            }
        }

        if (item.map) {
            const originalPosition = item.map.originalPositionFor(position);

            // Only return the original position if a matching line was found. If no
            // matching line is found then we return position instead, which will cause
            // the stack trace to print the path and line for the compiled file. It is
            // better to give a precise location in the compiled file than a vague
            // location in the original file.
            if (originalPosition.source !== null)
                return originalPosition;
        }

        return position;
    }

    function findSourceMap(source) {
        if (source === Script.fileName)
            return Script.sourceMap;
        else
            return null;
    }

    function cloneCallSite(frame) {
        const object = {};
        Object.getOwnPropertyNames(Object.getPrototypeOf(frame)).forEach(function (name) {
            object[name] = /^(?:is|get)/.test(name) ? function () {
                return frame[name].call(frame);
            } : frame[name];
        });
        object.toString = CallSiteToString;
        return object;
    }

    // This is copied almost verbatim from the V8 source code at
    // https://code.google.com/p/v8/source/browse/trunk/src/messages.js. The
    // implementation of wrapCallSite() used to just forward to the actual source
    // code of CallSite.prototype.toString but unfortunately a new release of V8
    // did something to the prototype chain and broke the shim. The only fix I
    // could find was copy/paste.
    function CallSiteToString() {
        let fileLocation = "";
        if (this.isNative()) {
            fileLocation = "native";
        } else {
            const fileName = this.getScriptNameOrSourceURL();
            if (!fileName && this.isEval()) {
                fileLocation = this.getEvalOrigin();
                fileLocation += ", "; // Expecting source position to follow.
            }

            if (fileName) {
                fileLocation += fileName;
            } else {
                // Source code does not originate from a file and is not native, but we
                // can still get the source position inside the source string, e.g. in
                // an eval string.
                fileLocation += "<anonymous>";
            }
            const lineNumber = this.getLineNumber();
            if (lineNumber !== null) {
                fileLocation += ":" + lineNumber;
                const columnNumber = this.getColumnNumber();
                if (columnNumber)
                    fileLocation += ":" + columnNumber;
            }
        }

        let line = "";
        const functionName = this.getFunctionName();
        let addSuffix = true;
        const isConstructor = this.isConstructor();
        const isMethodCall = !(this.isToplevel() || isConstructor);
        if (isMethodCall) {
            const typeName = this.getTypeName();
            const methodName = this.getMethodName();
            if (functionName) {
                if (typeName && functionName.indexOf(typeName) != 0) {
                    line += typeName + ".";
                }
                line += functionName;
                if (methodName && functionName.indexOf("." + methodName) != functionName.length - methodName.length - 1) {
                    line += " [as " + methodName + "]";
                }
            } else {
                line += typeName + "." + (methodName || "<anonymous>");
            }
        } else if (isConstructor) {
            line += "new " + (functionName || "<anonymous>");
        } else if (functionName) {
            line += functionName;
        } else {
            line += fileLocation;
            addSuffix = false;
        }
        if (addSuffix) {
            line += " (" + fileLocation + ")";
        }
        return line;
    }

    /*
     * Based on https://github.com/mozilla/source-map
     */

    /*
     *** source-map-consumer.js
     */
    const base64 = {};
    const base64VLQ = {};
    const binarySearch = {};

    function SourceMapConsumer(aSourceMap) {
        var sourceMap = aSourceMap;
        if (typeof aSourceMap === 'string') {
            sourceMap = JSON.parse(aSourceMap.replace(/^\)\]\}'/, ''));
        }

        return sourceMap.sections ? new IndexedSourceMapConsumer(sourceMap) : new BasicSourceMapConsumer(sourceMap);
    }

    SourceMapConsumer.fromSourceMap = function (aSourceMap) {
        return BasicSourceMapConsumer.fromSourceMap(aSourceMap);
    };

    SourceMapConsumer.prototype._version = 3;

    SourceMapConsumer.prototype.__generatedMappings = null;
    Object.defineProperty(SourceMapConsumer.prototype, '_generatedMappings', {
        get: function () {
            if (!this.__generatedMappings) {
                this._parseMappings(this._mappings, this.sourceRoot);
            }

            return this.__generatedMappings;
        }
    });

    SourceMapConsumer.prototype.__originalMappings = null;
    Object.defineProperty(SourceMapConsumer.prototype, '_originalMappings', {
        get: function () {
            if (!this.__originalMappings) {
                this._parseMappings(this._mappings, this.sourceRoot);
            }

            return this.__originalMappings;
        }
    });

    SourceMapConsumer.prototype._charIsMappingSeparator = function (aStr, index) {
        var c = aStr.charAt(index);
        return c === ";" || c === ",";
    };

    SourceMapConsumer.prototype._parseMappings = function (aStr, aSourceRoot) {
        throw new Error("Subclasses must implement _parseMappings");
    };

    SourceMapConsumer.GENERATED_ORDER = 1;
    SourceMapConsumer.ORIGINAL_ORDER = 2;

    SourceMapConsumer.GREATEST_LOWER_BOUND = 1;
    SourceMapConsumer.LEAST_UPPER_BOUND = 2;

    SourceMapConsumer.prototype.eachMapping = function (aCallback, aContext, aOrder) {
        var context = aContext || null;
        var order = aOrder || SourceMapConsumer.GENERATED_ORDER;

        var mappings;
        switch (order) {
            case SourceMapConsumer.GENERATED_ORDER:
                mappings = this._generatedMappings;
                break;
            case SourceMapConsumer.ORIGINAL_ORDER:
                mappings = this._originalMappings;
                break;
            default:
                throw new Error("Unknown order of iteration.");
        }

        var sourceRoot = this.sourceRoot;
        mappings.map(function (mapping) {
            var source = mapping.source === null ? null : this._sources.at(mapping.source);
            if (source !== null && sourceRoot !== null) {
                source = join(sourceRoot, source);
            }
            return {
                source: source,
                generatedLine: mapping.generatedLine,
                generatedColumn: mapping.generatedColumn,
                originalLine: mapping.originalLine,
                originalColumn: mapping.originalColumn,
                name: mapping.name === null ? null : this._names.at(mapping.name)
            };
        }, this).forEach(aCallback, context);
    };

    SourceMapConsumer.prototype.allGeneratedPositionsFor = function (aArgs) {
        var line = getArg(aArgs, 'line');

        var needle = {
            source: getArg(aArgs, 'source'),
            originalLine: line,
            originalColumn: getArg(aArgs, 'column', 0)
        };

        if (this.sourceRoot !== null) {
            needle.source = relative(this.sourceRoot, needle.source);
        }
        if (!this._sources.has(needle.source)) {
            return [];
        }
        needle.source = this._sources.indexOf(needle.source);

        var mappings = [];

        var index = this._findMapping(needle,
            this._originalMappings,
            "originalLine",
            "originalColumn",
            compareByOriginalPositions,
            binarySearch.LEAST_UPPER_BOUND);
        if (index >= 0) {
            var mapping = this._originalMappings[index];

            if (aArgs.column === undefined) {
                var originalLine = mapping.originalLine;

                while (mapping && mapping.originalLine === originalLine) {
                    mappings.push({
                        line: getArg(mapping, 'generatedLine', null),
                        column: getArg(mapping, 'generatedColumn', null),
                        lastColumn: getArg(mapping, 'lastGeneratedColumn', null)
                    });

                    mapping = this._originalMappings[++index];
                }
            } else {
                var originalColumn = mapping.originalColumn;

                while (mapping &&
                    mapping.originalLine === line &&
                    mapping.originalColumn == originalColumn) {
                    mappings.push({
                        line: getArg(mapping, 'generatedLine', null),
                        column: getArg(mapping, 'generatedColumn', null),
                        lastColumn: getArg(mapping, 'lastGeneratedColumn', null)
                    });

                    mapping = this._originalMappings[++index];
                }
            }
        }

        return mappings;
    };

    function BasicSourceMapConsumer(aSourceMap) {
        var sourceMap = aSourceMap;
        if (typeof aSourceMap === 'string') {
            sourceMap = JSON.parse(aSourceMap.replace(/^\)\]\}'/, ''));
        }

        var version = getArg(sourceMap, 'version');
        var sources = getArg(sourceMap, 'sources');
        var names = getArg(sourceMap, 'names', []);
        var sourceRoot = getArg(sourceMap, 'sourceRoot', null);
        var sourcesContent = getArg(sourceMap, 'sourcesContent', null);
        var mappings = getArg(sourceMap, 'mappings');
        var file = getArg(sourceMap, 'file', null);

        if (version != this._version) {
            throw new Error('Unsupported version: ' + version);
        }

        sources = sources
            .map(normalize)
            .map(function (source) {
                return sourceRoot && isAbsolute(sourceRoot) && isAbsolute(source) ? relative(sourceRoot, source) : source;
            });

        this._names = ArraySet.fromArray(names, true);
        this._sources = ArraySet.fromArray(sources, true);

        this.sourceRoot = sourceRoot;
        this.sourcesContent = sourcesContent;
        this._mappings = mappings;
        this.file = file;
    }

    BasicSourceMapConsumer.prototype = Object.create(SourceMapConsumer.prototype);
    BasicSourceMapConsumer.prototype.consumer = SourceMapConsumer;

    BasicSourceMapConsumer.fromSourceMap = function (aSourceMap) {
        var smc = Object.create(BasicSourceMapConsumer.prototype);

        var names = smc._names = ArraySet.fromArray(aSourceMap._names.toArray(), true);
        var sources = smc._sources = ArraySet.fromArray(aSourceMap._sources.toArray(), true);
        smc.sourceRoot = aSourceMap._sourceRoot;
        smc.sourcesContent = aSourceMap._generateSourcesContent(smc._sources.toArray(),
            smc.sourceRoot);
        smc.file = aSourceMap._file;

        var generatedMappings = aSourceMap._mappings.toArray().slice();
        var destGeneratedMappings = smc.__generatedMappings = [];
        var destOriginalMappings = smc.__originalMappings = [];

        for (var i = 0, length = generatedMappings.length; i < length; i++) {
            var srcMapping = generatedMappings[i];
            var destMapping = new Mapping();
            destMapping.generatedLine = srcMapping.generatedLine;
            destMapping.generatedColumn = srcMapping.generatedColumn;

            if (srcMapping.source) {
                destMapping.source = sources.indexOf(srcMapping.source);
                destMapping.originalLine = srcMapping.originalLine;
                destMapping.originalColumn = srcMapping.originalColumn;

                if (srcMapping.name) {
                    destMapping.name = names.indexOf(srcMapping.name);
                }

                destOriginalMappings.push(destMapping);
            }

            destGeneratedMappings.push(destMapping);
        }

        quickSort(smc.__originalMappings, compareByOriginalPositions);

        return smc;
    };

    BasicSourceMapConsumer.prototype._version = 3;

    Object.defineProperty(BasicSourceMapConsumer.prototype, 'sources', {
        get: function () {
            return this._sources.toArray().map(function (s) {
                return this.sourceRoot !== null ? join(this.sourceRoot, s) : s;
            }, this);
        }
    });

    function Mapping() {
        this.generatedLine = 0;
        this.generatedColumn = 0;
        this.source = null;
        this.originalLine = null;
        this.originalColumn = null;
        this.name = null;
    }

    BasicSourceMapConsumer.prototype._parseMappings = function (aStr, aSourceRoot) {
        var generatedLine = 1;
        var previousGeneratedColumn = 0;
        var previousOriginalLine = 0;
        var previousOriginalColumn = 0;
        var previousSource = 0;
        var previousName = 0;
        var length = aStr.length;
        var index = 0;
        var cachedSegments = {};
        var temp = {};
        var originalMappings = [];
        var generatedMappings = [];
        var mapping, str, segment, end, value;

        while (index < length) {
            if (aStr.charAt(index) === ';') {
                generatedLine++;
                index++;
                previousGeneratedColumn = 0;
            } else if (aStr.charAt(index) === ',') {
                index++;
            } else {
                mapping = new Mapping();
                mapping.generatedLine = generatedLine;

                for (end = index; end < length; end++) {
                    if (this._charIsMappingSeparator(aStr, end)) {
                        break;
                    }
                }
                str = aStr.slice(index, end);

                segment = cachedSegments[str];
                if (segment) {
                    index += str.length;
                } else {
                    segment = [];
                    while (index < end) {
                        base64VLQ.decode(aStr, index, temp);
                        value = temp.value;
                        index = temp.rest;
                        segment.push(value);
                    }

                    if (segment.length === 2) {
                        throw new Error('Found a source, but no line and column');
                    }

                    if (segment.length === 3) {
                        throw new Error('Found a source and line, but no column');
                    }

                    cachedSegments[str] = segment;
                }

                mapping.generatedColumn = previousGeneratedColumn + segment[0];
                previousGeneratedColumn = mapping.generatedColumn;

                if (segment.length > 1) {
                    mapping.source = previousSource + segment[1];
                    previousSource += segment[1];

                    mapping.originalLine = previousOriginalLine + segment[2];
                    previousOriginalLine = mapping.originalLine;
                    mapping.originalLine += 1;

                    mapping.originalColumn = previousOriginalColumn + segment[3];
                    previousOriginalColumn = mapping.originalColumn;

                    if (segment.length > 4) {
                        mapping.name = previousName + segment[4];
                        previousName += segment[4];
                    }
                }

                generatedMappings.push(mapping);
                if (typeof mapping.originalLine === 'number') {
                    originalMappings.push(mapping);
                }
            }
        }

        quickSort(generatedMappings, compareByGeneratedPositionsDeflated);
        this.__generatedMappings = generatedMappings;

        quickSort(originalMappings, compareByOriginalPositions);
        this.__originalMappings = originalMappings;
    };

    BasicSourceMapConsumer.prototype._findMapping = function (aNeedle, aMappings, aLineName, aColumnName, aComparator, aBias) {
        if (aNeedle[aLineName] <= 0) {
            throw new TypeError('Line must be greater than or equal to 1, got ' + aNeedle[aLineName]);
        }
        if (aNeedle[aColumnName] < 0) {
            throw new TypeError('Column must be greater than or equal to 0, got ' + aNeedle[aColumnName]);
        }

        return binarySearch.search(aNeedle, aMappings, aComparator, aBias);
    };

    BasicSourceMapConsumer.prototype.computeColumnSpans = function () {
        for (var index = 0; index < this._generatedMappings.length; ++index) {
            var mapping = this._generatedMappings[index];

            if (index + 1 < this._generatedMappings.length) {
                var nextMapping = this._generatedMappings[index + 1];

                if (mapping.generatedLine === nextMapping.generatedLine) {
                    mapping.lastGeneratedColumn = nextMapping.generatedColumn - 1;
                    continue;
                }
            }

            mapping.lastGeneratedColumn = Infinity;
        }
    };

    BasicSourceMapConsumer.prototype.originalPositionFor = function (aArgs) {
        var needle = {
            generatedLine: getArg(aArgs, 'line'),
            generatedColumn: getArg(aArgs, 'column')
        };

        var index = this._findMapping(
            needle,
            this._generatedMappings,
            "generatedLine",
            "generatedColumn",
            compareByGeneratedPositionsDeflated,
            getArg(aArgs, 'bias', SourceMapConsumer.GREATEST_LOWER_BOUND)
        );

        if (index >= 0) {
            var mapping = this._generatedMappings[index];

            if (mapping.generatedLine === needle.generatedLine) {
                var source = getArg(mapping, 'source', null);
                if (source !== null) {
                    source = this._sources.at(source);
                    if (this.sourceRoot !== null) {
                        source = join(this.sourceRoot, source);
                    }
                }
                var name = getArg(mapping, 'name', null);
                if (name !== null) {
                    name = this._names.at(name);
                }
                return {
                    source: source,
                    line: getArg(mapping, 'originalLine', null),
                    column: getArg(mapping, 'originalColumn', null),
                    name: name
                };
            }
        }

        return {
            source: null,
            line: null,
            column: null,
            name: null
        };
    };

    BasicSourceMapConsumer.prototype.hasContentsOfAllSources = function () {
        if (!this.sourcesContent) {
            return false;
        }
        return this.sourcesContent.length >= this._sources.size() &&
            !this.sourcesContent.some(function (sc) {
                return sc === null;
            });
    };

    BasicSourceMapConsumer.prototype.sourceContentFor = function (aSource, nullOnMissing) {
        if (!this.sourcesContent) {
            return null;
        }

        if (this.sourceRoot !== null) {
            aSource = relative(this.sourceRoot, aSource);
        }

        if (this._sources.has(aSource)) {
            return this.sourcesContent[this._sources.indexOf(aSource)];
        }

        var url;
        if (this.sourceRoot !== null && (url = urlParse(this.sourceRoot))) {
            var fileUriAbsPath = aSource.replace(/^file:\/\//, "");
            if (url.scheme == "file" && this._sources.has(fileUriAbsPath)) {
                return this.sourcesContent[this._sources.indexOf(fileUriAbsPath)];
            }

            if ((!url.path || url.path == "/") && this._sources.has("/" + aSource)) {
                return this.sourcesContent[this._sources.indexOf("/" + aSource)];
            }
        }

        if (nullOnMissing) {
            return null;
        } else {
            throw new Error('"' + aSource + '" is not in the SourceMap.');
        }
    };

    BasicSourceMapConsumer.prototype.generatedPositionFor = function (aArgs) {
        var source = getArg(aArgs, 'source');
        if (this.sourceRoot !== null) {
            source = relative(this.sourceRoot, source);
        }
        if (!this._sources.has(source)) {
            return {
                line: null,
                column: null,
                lastColumn: null
            };
        }
        source = this._sources.indexOf(source);

        var needle = {
            source: source,
            originalLine: getArg(aArgs, 'line'),
            originalColumn: getArg(aArgs, 'column')
        };

        var index = this._findMapping(
            needle,
            this._originalMappings,
            "originalLine",
            "originalColumn",
            compareByOriginalPositions,
            getArg(aArgs, 'bias', SourceMapConsumer.GREATEST_LOWER_BOUND)
        );

        if (index >= 0) {
            var mapping = this._originalMappings[index];

            if (mapping.source === needle.source) {
                return {
                    line: getArg(mapping, 'generatedLine', null),
                    column: getArg(mapping, 'generatedColumn', null),
                    lastColumn: getArg(mapping, 'lastGeneratedColumn', null)
                };
            }
        }

        return {
            line: null,
            column: null,
            lastColumn: null
        };
    };

    function IndexedSourceMapConsumer(aSourceMap) {
        var sourceMap = aSourceMap;
        if (typeof aSourceMap === 'string') {
            sourceMap = JSON.parse(aSourceMap.replace(/^\)\]\}'/, ''));
        }

        var version = getArg(sourceMap, 'version');
        var sections = getArg(sourceMap, 'sections');

        if (version != this._version) {
            throw new Error('Unsupported version: ' + version);
        }

        this._sources = new ArraySet();
        this._names = new ArraySet();

        var lastOffset = {
            line: -1,
            column: 0
        };
        this._sections = sections.map(function (s) {
            if (s.url) {
                throw new Error('Support for url field in sections not implemented.');
            }
            var offset = getArg(s, 'offset');
            var offsetLine = getArg(offset, 'line');
            var offsetColumn = getArg(offset, 'column');

            if (offsetLine < lastOffset.line ||
                (offsetLine === lastOffset.line && offsetColumn < lastOffset.column)) {
                throw new Error('Section offsets must be ordered and non-overlapping.');
            }
            lastOffset = offset;

            return {
                generatedOffset: {
                    generatedLine: offsetLine + 1,
                    generatedColumn: offsetColumn + 1
                },
                consumer: new SourceMapConsumer(getArg(s, 'map'))
            };
        });
    }

    IndexedSourceMapConsumer.prototype = Object.create(SourceMapConsumer.prototype);
    IndexedSourceMapConsumer.prototype.constructor = SourceMapConsumer;

    IndexedSourceMapConsumer.prototype._version = 3;

    Object.defineProperty(IndexedSourceMapConsumer.prototype, 'sources', {
        get: function () {
            var sources = [];
            for (var i = 0; i < this._sections.length; i++) {
                for (var j = 0; j < this._sections[i].consumer.sources.length; j++) {
                    sources.push(this._sections[i].consumer.sources[j]);
                }
            }
            return sources;
        }
    });

    IndexedSourceMapConsumer.prototype.originalPositionFor = function (aArgs) {
        var needle = {
            generatedLine: getArg(aArgs, 'line'),
            generatedColumn: getArg(aArgs, 'column')
        };

        var sectionIndex = binarySearch.search(needle, this._sections,
            function (needle, section) {
                var cmp = needle.generatedLine - section.generatedOffset.generatedLine;
                if (cmp) {
                    return cmp;
                }

                return (needle.generatedColumn -
                    section.generatedOffset.generatedColumn);
            });
        var section = this._sections[sectionIndex];

        if (!section) {
            return {
                source: null,
                line: null,
                column: null,
                name: null
            };
        }

        return section.consumer.originalPositionFor({
            line: needle.generatedLine -
                (section.generatedOffset.generatedLine - 1),
            column: needle.generatedColumn -
                (section.generatedOffset.generatedLine === needle.generatedLine ? section.generatedOffset.generatedColumn - 1 : 0),
            bias: aArgs.bias
        });
    };

    IndexedSourceMapConsumer.prototype.hasContentsOfAllSources = function () {
        return this._sections.every(function (s) {
            return s.consumer.hasContentsOfAllSources();
        });
    };

    IndexedSourceMapConsumer.prototype.sourceContentFor = function (aSource, nullOnMissing) {
        for (var i = 0; i < this._sections.length; i++) {
            var section = this._sections[i];

            var content = section.consumer.sourceContentFor(aSource, true);
            if (content) {
                return content;
            }
        }
        if (nullOnMissing) {
            return null;
        } else {
            throw new Error('"' + aSource + '" is not in the SourceMap.');
        }
    };

    IndexedSourceMapConsumer.prototype.generatedPositionFor = function (aArgs) {
        for (var i = 0; i < this._sections.length; i++) {
            var section = this._sections[i];

            if (section.consumer.sources.indexOf(getArg(aArgs, 'source')) === -1) {
                continue;
            }
            var generatedPosition = section.consumer.generatedPositionFor(aArgs);
            if (generatedPosition) {
                var ret = {
                    line: generatedPosition.line +
                        (section.generatedOffset.generatedLine - 1),
                    column: generatedPosition.column +
                        (section.generatedOffset.generatedLine === generatedPosition.line ? section.generatedOffset.generatedColumn - 1 : 0)
                };
                return ret;
            }
        }

        return {
            line: null,
            column: null
        };
    };

    IndexedSourceMapConsumer.prototype._parseMappings = function (aStr, aSourceRoot) {
        this.__generatedMappings = [];
        this.__originalMappings = [];
        for (var i = 0; i < this._sections.length; i++) {
            var section = this._sections[i];
            var sectionMappings = section.consumer._generatedMappings;
            for (var j = 0; j < sectionMappings.length; j++) {
                var mapping = sectionMappings[i];

                var source = section.consumer._sources.at(mapping.source);
                if (section.consumer.sourceRoot !== null) {
                    source = join(section.consumer.sourceRoot, source);
                }
                this._sources.add(source);
                source = this._sources.indexOf(source);

                var name = section.consumer._names.at(mapping.name);
                this._names.add(name);
                name = this._names.indexOf(name);

                var adjustedMapping = {
                    source: source,
                    generatedLine: mapping.generatedLine +
                        (section.generatedOffset.generatedLine - 1),
                    generatedColumn: mapping.column +
                        (section.generatedOffset.generatedLine === mapping.generatedLine) ? section.generatedOffset.generatedColumn - 1 : 0,
                    originalLine: mapping.originalLine,
                    originalColumn: mapping.originalColumn,
                    name: name
                };

                this.__generatedMappings.push(adjustedMapping);
                if (typeof adjustedMapping.originalLine === 'number') {
                    this.__originalMappings.push(adjustedMapping);
                }
            }
        }

        quickSort(this.__generatedMappings, compareByGeneratedPositionsDeflated);
        quickSort(this.__originalMappings, compareByOriginalPositions);
    };

    /*
     *** array-set.js
     */
    function ArraySet() {
        this._array = [];
        this._set = {};
    }

    ArraySet.fromArray = function (aArray, aAllowDuplicates) {
        var set = new ArraySet();
        for (var i = 0, len = aArray.length; i < len; i++) {
            set.add(aArray[i], aAllowDuplicates);
        }
        return set;
    };

    ArraySet.prototype.size = function () {
        return Object.getOwnPropertyNames(this._set).length;
    };

    ArraySet.prototype.add = function (aStr, aAllowDuplicates) {
        var sStr = toSetString(aStr);
        var isDuplicate = this._set.hasOwnProperty(sStr);
        var idx = this._array.length;
        if (!isDuplicate || aAllowDuplicates) {
            this._array.push(aStr);
        }
        if (!isDuplicate) {
            this._set[sStr] = idx;
        }
    };

    ArraySet.prototype.has = function (aStr) {
        var sStr = toSetString(aStr);
        return this._set.hasOwnProperty(sStr);
    };

    ArraySet.prototype.indexOf = function (aStr) {
        var sStr = toSetString(aStr);
        if (this._set.hasOwnProperty(sStr)) {
            return this._set[sStr];
        }
        throw new Error('"' + aStr + '" is not in the set.');
    };

    ArraySet.prototype.at = function (aIdx) {
        if (aIdx >= 0 && aIdx < this._array.length) {
            return this._array[aIdx];
        }
        throw new Error('No element indexed by ' + aIdx);
    };

    ArraySet.prototype.toArray = function () {
        return this._array.slice();
    };

    /*
     *** binary-search.js
     */
    binarySearch.GREATEST_LOWER_BOUND = 1;
    binarySearch.LEAST_UPPER_BOUND = 2;

    binarySearch.search = function (aNeedle, aHaystack, aCompare, aBias) {
        if (aHaystack.length === 0) {
            return -1;
        }

        var index = recursiveSearch(-1, aHaystack.length, aNeedle, aHaystack,
            aCompare, aBias || binarySearch.GREATEST_LOWER_BOUND);
        if (index < 0) {
            return -1;
        }

        while (index - 1 >= 0) {
            if (aCompare(aHaystack[index], aHaystack[index - 1], true) !== 0) {
                break;
            }
            --index;
        }

        return index;
    };

    function recursiveSearch(aLow, aHigh, aNeedle, aHaystack, aCompare, aBias) {
        var mid = Math.floor((aHigh - aLow) / 2) + aLow;
        var cmp = aCompare(aNeedle, aHaystack[mid], true);
        if (cmp === 0) {
            return mid;
        } else if (cmp > 0) {
            if (aHigh - mid > 1) {
                return recursiveSearch(mid, aHigh, aNeedle, aHaystack, aCompare, aBias);
            }

            if (aBias == binarySearch.LEAST_UPPER_BOUND) {
                return aHigh < aHaystack.length ? aHigh : -1;
            } else {
                return mid;
            }
        } else {
            if (mid - aLow > 1) {
                return recursiveSearch(aLow, mid, aNeedle, aHaystack, aCompare, aBias);
            }

            if (aBias == binarySearch.LEAST_UPPER_BOUND) {
                return mid;
            } else {
                return aLow < 0 ? -1 : aLow;
            }
        }
    }

    /*
     *** quick-sort.js
     */
    function quickSort(ary, comparator) {
        doQuickSort(ary, comparator, 0, ary.length - 1);
    }

    function doQuickSort(ary, comparator, p, r) {
        if (p < r) {
            var pivotIndex = randomIntInRange(p, r);
            var i = p - 1;

            swap(ary, pivotIndex, r);
            var pivot = ary[r];

            for (var j = p; j < r; j++) {
                if (comparator(ary[j], pivot) <= 0) {
                    i += 1;
                    swap(ary, i, j);
                }
            }

            swap(ary, i + 1, j);
            var q = i + 1;

            doQuickSort(ary, comparator, p, q - 1);
            doQuickSort(ary, comparator, q + 1, r);
        }
    }

    function swap(ary, x, y) {
        var temp = ary[x];
        ary[x] = ary[y];
        ary[y] = temp;
    }

    function randomIntInRange(low, high) {
        return Math.round(low + (Math.random() * (high - low)));
    }

    /*
     *** base64-vlq.js
     */
    const VLQ_BASE_SHIFT = 5;
    const VLQ_BASE = 1 << VLQ_BASE_SHIFT;
    const VLQ_BASE_MASK = VLQ_BASE - 1;
    const VLQ_CONTINUATION_BIT = VLQ_BASE;

    base64VLQ.encode = function (aValue) {
        var encoded = "";
        var digit;

        var vlq = toVLQSigned(aValue);

        do {
            digit = vlq & VLQ_BASE_MASK;
            vlq >>>= VLQ_BASE_SHIFT;
            if (vlq > 0) {
                digit |= VLQ_CONTINUATION_BIT;
            }
            encoded += base64.encode(digit);
        } while (vlq > 0);

        return encoded;
    };

    base64VLQ.decode = function (aStr, aIndex, aOutParam) {
        var strLen = aStr.length;
        var result = 0;
        var shift = 0;
        var continuation, digit;

        do {
            if (aIndex >= strLen) {
                throw new Error("Expected more digits in base 64 VLQ value.");
            }

            digit = base64.decode(aStr.charCodeAt(aIndex++));
            if (digit === -1) {
                throw new Error("Invalid base64 digit: " + aStr.charAt(aIndex - 1));
            }

            continuation = !!(digit & VLQ_CONTINUATION_BIT);
            digit &= VLQ_BASE_MASK;
            result = result + (digit << shift);
            shift += VLQ_BASE_SHIFT;
        } while (continuation);

        aOutParam.value = fromVLQSigned(result);
        aOutParam.rest = aIndex;
    };

    function toVLQSigned(aValue) {
        return aValue < 0 ? ((-aValue) << 1) + 1 : (aValue << 1) + 0;
    }

    function fromVLQSigned(aValue) {
        var isNegative = (aValue & 1) === 1;
        var shifted = aValue >> 1;
        return isNegative ? -shifted : shifted;
    }

    /*
     *** base64.js
     */
    const intToCharMap = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.split('');

    base64.encode = function (number) {
        if (0 <= number && number < intToCharMap.length) {
            return intToCharMap[number];
        }
        throw new TypeError("Must be between 0 and 63: " + number);
    };

    base64.decode = function (charCode) {
        var bigA = 65;
        var bigZ = 90;

        var littleA = 97;
        var littleZ = 122;

        var zero = 48;
        var nine = 57;

        var plus = 43;
        var slash = 47;

        var littleOffset = 26;
        var numberOffset = 52;

        if (bigA <= charCode && charCode <= bigZ) {
            return (charCode - bigA);
        }

        if (littleA <= charCode && charCode <= littleZ) {
            return (charCode - littleA + littleOffset);
        }

        if (zero <= charCode && charCode <= nine) {
            return (charCode - zero + numberOffset);
        }

        if (charCode == plus) {
            return 62;
        }

        if (charCode == slash) {
            return 63;
        }

        return -1;
    };

    /*
     *** util.js
     */
    function getArg(aArgs, aName, aDefaultValue) {
        if (aName in aArgs) {
            return aArgs[aName];
        } else if (arguments.length === 3) {
            return aDefaultValue;
        } else {
            throw new Error('"' + aName + '" is a required argument.');
        }
    }

    const urlRegexp = /^(?:([\w+\-.]+):)?\/\/(?:(\w+:\w+)@)?([\w.]*)(?::(\d+))?(\S*)$/;
    const dataUrlRegexp = /^data:.+\,.+$/;

    function urlParse(aUrl) {
        var match = aUrl.match(urlRegexp);
        if (!match) {
            return null;
        }
        return {
            scheme: match[1],
            auth: match[2],
            host: match[3],
            port: match[4],
            path: match[5]
        };
    }

    function urlGenerate(aParsedUrl) {
        var url = '';
        if (aParsedUrl.scheme) {
            url += aParsedUrl.scheme + ':';
        }
        url += '//';
        if (aParsedUrl.auth) {
            url += aParsedUrl.auth + '@';
        }
        if (aParsedUrl.host) {
            url += aParsedUrl.host;
        }
        if (aParsedUrl.port) {
            url += ":" + aParsedUrl.port;
        }
        if (aParsedUrl.path) {
            url += aParsedUrl.path;
        }
        return url;
    }

    function normalize(aPath) {
        var path = aPath;
        var url = urlParse(aPath);
        if (url) {
            if (!url.path) {
                return aPath;
            }
            path = url.path;
        }
        var pathIsAbsolute = isAbsolute(path);

        var parts = path.split(/\/+/);
        for (var part, up = 0, i = parts.length - 1; i >= 0; i--) {
            part = parts[i];
            if (part === '.') {
                parts.splice(i, 1);
            } else if (part === '..') {
                up++;
            } else if (up > 0) {
                if (part === '') {
                    parts.splice(i + 1, up);
                    up = 0;
                } else {
                    parts.splice(i, 2);
                    up--;
                }
            }
        }
        path = parts.join('/');

        if (path === '') {
            path = pathIsAbsolute ? '/' : '.';
        }

        if (url) {
            url.path = path;
            return urlGenerate(url);
        }
        return path;
    }

    function join(aRoot, aPath) {
        if (aRoot === "") {
            aRoot = ".";
        }
        if (aPath === "") {
            aPath = ".";
        }
        var aPathUrl = urlParse(aPath);
        var aRootUrl = urlParse(aRoot);
        if (aRootUrl) {
            aRoot = aRootUrl.path || '/';
        }

        if (aPathUrl && !aPathUrl.scheme) {
            if (aRootUrl) {
                aPathUrl.scheme = aRootUrl.scheme;
            }
            return urlGenerate(aPathUrl);
        }

        if (aPathUrl || aPath.match(dataUrlRegexp)) {
            return aPath;
        }

        if (aRootUrl && !aRootUrl.host && !aRootUrl.path) {
            aRootUrl.host = aPath;
            return urlGenerate(aRootUrl);
        }

        var joined = aPath.charAt(0) === '/' ? aPath : normalize(aRoot.replace(/\/+$/, '') + '/' + aPath);

        if (aRootUrl) {
            aRootUrl.path = joined;
            return urlGenerate(aRootUrl);
        }
        return joined;
    }

    function isAbsolute(aPath) {
        return aPath.charAt(0) === '/' || !!aPath.match(urlRegexp);
    }

    function relative(aRoot, aPath) {
        if (aRoot === "") {
            aRoot = ".";
        }

        aRoot = aRoot.replace(/\/$/, '');

        var level = 0;
        while (aPath.indexOf(aRoot + '/') !== 0) {
            var index = aRoot.lastIndexOf("/");
            if (index < 0) {
                return aPath;
            }

            aRoot = aRoot.slice(0, index);
            if (aRoot.match(/^([^\/]+:\/)?\/*$/)) {
                return aPath;
            }

            ++level;
        }

        return new Array(level + 1).join("../") + aPath.substr(aRoot.length + 1);
    }

    function toSetString(aStr) {
        return '$' + aStr;
    }

    function compareByOriginalPositions(mappingA, mappingB, onlyCompareOriginal) {
        var cmp = mappingA.source - mappingB.source;
        if (cmp !== 0) {
            return cmp;
        }

        cmp = mappingA.originalLine - mappingB.originalLine;
        if (cmp !== 0) {
            return cmp;
        }

        cmp = mappingA.originalColumn - mappingB.originalColumn;
        if (cmp !== 0 || onlyCompareOriginal) {
            return cmp;
        }

        cmp = mappingA.generatedColumn - mappingB.generatedColumn;
        if (cmp !== 0) {
            return cmp;
        }

        cmp = mappingA.generatedLine - mappingB.generatedLine;
        if (cmp !== 0) {
            return cmp;
        }

        return mappingA.name - mappingB.name;
    }

    function compareByGeneratedPositionsDeflated(mappingA, mappingB, onlyCompareGenerated) {
        var cmp = mappingA.generatedLine - mappingB.generatedLine;
        if (cmp !== 0) {
            return cmp;
        }

        cmp = mappingA.generatedColumn - mappingB.generatedColumn;
        if (cmp !== 0 || onlyCompareGenerated) {
            return cmp;
        }

        cmp = mappingA.source - mappingB.source;
        if (cmp !== 0) {
            return cmp;
        }

        cmp = mappingA.originalLine - mappingB.originalLine;
        if (cmp !== 0) {
            return cmp;
        }

        cmp = mappingA.originalColumn - mappingB.originalColumn;
        if (cmp !== 0) {
            return cmp;
        }

        return mappingA.name - mappingB.name;
    }

    function strcmp(aStr1, aStr2) {
        if (aStr1 === aStr2) {
            return 0;
        }

        if (aStr1 > aStr2) {
            return 1;
        }

        return -1;
    }
}).call(this);
