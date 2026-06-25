const bufferSize = 512 * 1024;
const startThreshold = 50 * 1024 * 1024;
const maxChunkLen = 64 * 1024;
const flushTime = 10;
const chunkIdxLookup = new Uint8Array([
    0, 0, 0, 1, 2, 3, 4, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 10, 10,
    10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12
]);
const lowerBounds = new Uint16Array([1024, 1536, 2048, 2560, 3072, 3584, 4096, 5120, 6144, 7168, 8192, 12288, 20480, 28672]);
const manualPipe = async (readable, writable, close) => {
    const safeBufferSize = bufferSize - maxChunkLen, fastFlushOffset = Math.max(bufferSize / flushTime * 2, maxChunkLen * 2);
    let buffer = new ArrayBuffer(bufferSize), spareBuffer = new ArrayBuffer(maxChunkLen), bufferView = new Uint8Array(buffer);
    let offset = 0, totalBytes = 0, time = 1, timerId = null, resume = null, isReading = false, needsFlush = false, protectFlush = false;
    let globalCount = new Uint32Array(14), globalBytes = new Uint32Array(14);
    let statCount = 0, totalCount = 0, totalGlobalBytes = 0, isClose = false, fastFlush = true;
    const flushBuffer = () => {
        if (isReading) return needsFlush = true;
        fastFlush = offset < fastFlushOffset;
        if (offset > 0 && !isClose) {
            offset > safeBufferSize
                ? (writable.send(bufferView.subarray(0, offset)), buffer = new ArrayBuffer(bufferSize), bufferView = new Uint8Array(buffer))
                : writable.send(bufferView.slice(0, offset));
            offset = 0;
        }
        needsFlush = false, protectFlush = false, timerId && (clearTimeout(timerId), timerId = null), resume?.(), resume = null;
    };
    const reader = readable.getReader({mode: 'byob'});
    try {
        while (true) {
            const useSpare = offset > 0 && protectFlush;
            let readBuffer = buffer, readOffset = offset;
            isReading = offset > 0;
            useSpare && (readBuffer = spareBuffer, readOffset = 0, isReading = false);
            const {done, value} = await reader.read(new Uint8Array(readBuffer, readOffset, maxChunkLen));
            isReading = false;
            useSpare ? (bufferView.set(value, offset), spareBuffer = value.buffer) : (buffer = value.buffer, bufferView = new Uint8Array(buffer));
            if (done) break;
            const chunkLen = value.byteLength;
            offset += chunkLen;
            if (needsFlush) {
                flushBuffer();
            } else {
                if (fastFlush) {
                    time = 1;
                } else {
                    const idx = chunkLen >= 30720 ? 13 : chunkIdxLookup[chunkLen >> 9];
                    globalCount[idx]++, globalBytes[idx] += chunkLen, statCount++, totalCount++, totalGlobalBytes += chunkLen;
                    if (statCount > 16384) {
                        statCount = 0, totalCount >>>= 1, totalGlobalBytes >>>= 1;
                        for (let i = 0; i < 14; i++) globalCount[i] >>>= 1, globalBytes[i] >>>= 1;
                    }
                    let maxScore = -1, maxIdx = 0;
                    const byteFactor = 0.25 * totalCount / totalGlobalBytes;
                    for (let i = 0; i < 14; i++) {
                        const score = globalCount[i] + globalBytes[i] * byteFactor;
                        score > maxScore && (maxScore = score, maxIdx = i);
                    }
                    if (chunkLen < lowerBounds[maxIdx]) {
                        totalBytes = 0, time = 1;
                    } else if ((totalBytes += chunkLen) > startThreshold) time = flushTime;
                }
                timerId ||= setTimeout(flushBuffer, time), protectFlush = chunkLen < maxChunkLen;
                offset > safeBufferSize && (time === flushTime ? await new Promise(r => resume = r) : flushBuffer());
            }
        }
    } catch {close?.(), isClose = true} finally {isReading = false, flushBuffer()}
};
const manualPipe = async (readable, writable, close) => {
    const safeBufferSize = bufferSize - maxChunkLen, fastFlushOffset = bufferSize >> 1;
    let buffer = new ArrayBuffer(bufferSize), spareBuffer = new ArrayBuffer(maxChunkLen), bufferView = new Uint8Array(buffer);
    let offset = 0, totalBytes = 0, time = 1, timerId = null, resume = null, isReading = false, needsFlush = false, protectFlush = false;
    let isClose = false, fastFlush = true;
    const flushBuffer = () => {
        if (isReading) return needsFlush = true;
        fastFlush = offset < fastFlushOffset;
        if (offset > 0 && !isClose) {
            offset > safeBufferSize
                ? (writable.send(bufferView.subarray(0, offset)), buffer = new ArrayBuffer(bufferSize), bufferView = new Uint8Array(buffer))
                : writable.send(bufferView.slice(0, offset));
            offset = 0;
        }
        needsFlush = false, protectFlush = false, timerId && (clearTimeout(timerId), timerId = null), resume?.(), resume = null;
    };
    const reader = readable.getReader({mode: 'byob'});
    try {
        while (true) {
            const useSpare = offset > 0 && protectFlush;
            let readBuffer = buffer, readOffset = offset;
            isReading = offset > 0;
            useSpare && (readBuffer = spareBuffer, readOffset = 0, isReading = false);
            const {done, value} = await reader.read(new Uint8Array(readBuffer, readOffset, maxChunkLen));
            isReading = false;
            useSpare ? (bufferView.set(value, offset), spareBuffer = value.buffer) : (buffer = value.buffer, bufferView = new Uint8Array(buffer));
            if (done) break;
            const chunkLen = value.byteLength;
            offset += chunkLen;
            if (needsFlush) {
                flushBuffer();
            } else {
                if (fastFlush || chunkLen < 28672) {
                    totalBytes = 0, time = 1;
                } else if ((totalBytes += chunkLen) > startThreshold) time = flushTime;
                timerId ||= setTimeout(flushBuffer, time), protectFlush = chunkLen < maxChunkLen;
                offset > safeBufferSize && (time === flushTime ? await new Promise(r => resume = r) : flushBuffer());
            }
        }
    } catch {close?.(), isClose = true} finally {isReading = false, flushBuffer()}
};
const manualPipe = async (readable, writable, close) => {
    const safeBufferSize = bufferSize - maxChunkLen, halfChunkLen = maxChunkLen >> 1, directBufSize = halfChunkLen * 3, fastFlushOffset = bufferSize >> 1;
    let buffer, bufferView, spareBuffer = new ArrayBuffer(maxChunkLen);
    let offset = 0, totalBytes = 0, timerId = null, resume = null, isReading = false, needsFlush = false, protectFlush = false;
    let directBuf = new Uint8Array(directBufSize), directOff = 0, directTimer = null, isClose = false, fastFlush = true;
    const flushDirect = () => {
        directTimer && (clearTimeout(directTimer), directTimer = null);
        if (directOff > 0 && !isClose) {
            directOff === directBufSize
                ? (writable.send(directBuf), directBuf = new Uint8Array(directBufSize))
                : writable.send(directBuf.slice(0, directOff));
        }
        directOff = 0;
    };

    const flushBuffer = () => {
        if (isReading) return needsFlush = true;
        fastFlush = offset < fastFlushOffset;
        if (offset > 0 && !isClose) {
            offset > safeBufferSize
                ? (writable.send(bufferView.subarray(0, offset)), fastFlush || (buffer = new ArrayBuffer(bufferSize), bufferView = new Uint8Array(buffer)))
                : writable.send(bufferView.slice(0, offset));
            offset = 0;
        }
        fastFlush && (totalBytes = 0, directBuf ||= new Uint8Array(directBufSize), buffer = null, bufferView = null);
        needsFlush = false, protectFlush = false, timerId && (clearTimeout(timerId), timerId = null), resume?.(), resume = null;
    };
    const reader = readable.getReader({mode: 'byob'});
    try {
        while (true) {
            if (fastFlush) {
                const {done, value} = await reader.read(new Uint8Array(spareBuffer));
                if (done) break;
                const chunkLen = value.byteLength;
                if (!chunkLen) continue;
                if (chunkLen >= halfChunkLen) {
                    flushDirect(), writable.send(value), spareBuffer = new ArrayBuffer(maxChunkLen);
                } else if (directOff + chunkLen > directBufSize) {
                    flushDirect(), directBuf.set(value, 0), directOff = chunkLen, directTimer = setTimeout(flushDirect, 1), spareBuffer = value.buffer;
                } else {
                    directBuf.set(value, directOff), directOff += chunkLen, directTimer ||= setTimeout(flushDirect, 1), spareBuffer = value.buffer;
                }
                if (chunkLen < 28672) {
                    totalBytes = 0;
                } else if ((totalBytes += chunkLen) > startThreshold) {
                    flushDirect(), fastFlush = false, buffer = new ArrayBuffer(bufferSize), bufferView = new Uint8Array(buffer), directBuf = null;
                }
            } else {
                const useSpare = offset > 0 && protectFlush;
                let readBuffer = buffer, readOffset = offset;
                isReading = offset > 0;
                useSpare && (readBuffer = spareBuffer, readOffset = 0, isReading = false);
                const {done, value} = await reader.read(new Uint8Array(readBuffer, readOffset, maxChunkLen));
                isReading = false;
                useSpare ? (bufferView.set(value, offset), spareBuffer = value.buffer) : (buffer = value.buffer, bufferView = new Uint8Array(buffer));
                if (done) break;
                const chunkLen = value.byteLength;
                offset += chunkLen;
                if (needsFlush) {
                    flushBuffer();
                } else if (chunkLen < 28672) {
                    flushBuffer(), fastFlush = true, totalBytes = 0, directBuf = new Uint8Array(directBufSize), buffer = null, bufferView = null;
                } else {
                    timerId ||= setTimeout(flushBuffer, flushTime), protectFlush = chunkLen < maxChunkLen;
                    offset > safeBufferSize && await new Promise(r => resume = r);
                }
            }
        }
    } catch {close?.(), isClose = true} finally {isReading = false, flushDirect(), flushBuffer()}
};
const manualPipe = async (readable, writable, close) => {
    const safeBufferSize = bufferSize - maxChunkLen, halfChunkLen = maxChunkLen >> 1, directBufSize = halfChunkLen * 3, fastFlushOffset = bufferSize >> 1;
    let buffer, bufferView, spareBuffer = new ArrayBuffer(maxChunkLen);
    let offset = 0, totalBytes = 0, timerId = null, resume = null, isReading = false, needsFlush = false, protectFlush = false;
    let directBuf = new Uint8Array(directBufSize), directOff = 0, directTimer = null, isClose = false, fastFlush = true;
    let globalCount = new Uint32Array(14), globalBytes = new Uint32Array(14);
    let statCount = 0, totalCount = 0, totalGlobalBytes = 0;
    const updateChunkStats = (chunkLen, decay) => {
        const idx = chunkLen >= 30720 ? 13 : chunkIdxLookup[chunkLen >> 9];
        globalCount[idx]++, globalBytes[idx] += chunkLen, statCount++, totalCount++, totalGlobalBytes += chunkLen;
        if (decay && statCount > 16384) {
            statCount = 0, totalCount >>>= 1, totalGlobalBytes >>>= 1;
            for (let i = 0; i < 14; i++) globalCount[i] >>>= 1, globalBytes[i] >>>= 1;
        }
        let maxScore = -1, maxIdx = 0;
        const byteFactor = 0.25 * totalCount / totalGlobalBytes;
        for (let i = 0; i < 14; i++) {
            const score = globalCount[i] + globalBytes[i] * byteFactor;
            score > maxScore && (maxScore = score, maxIdx = i);
        }
        return maxIdx;
    };
    const flushDirect = () => {
        directTimer && (clearTimeout(directTimer), directTimer = null);
        if (directOff > 0 && !isClose) {
            directOff === directBufSize
                ? (writable.send(directBuf), directBuf = new Uint8Array(directBufSize))
                : writable.send(directBuf.slice(0, directOff));
        }
        directOff = 0;
    };
    const flushBuffer = () => {
        if (isReading) return needsFlush = true;
        fastFlush = offset < fastFlushOffset;
        if (offset > 0 && !isClose) {
            offset > safeBufferSize
                ? (writable.send(bufferView.subarray(0, offset)), fastFlush || (buffer = new ArrayBuffer(bufferSize), bufferView = new Uint8Array(buffer)))
                : writable.send(bufferView.slice(0, offset));
            offset = 0;
        }
        fastFlush && (totalBytes = 0, directBuf ||= new Uint8Array(directBufSize), buffer = null, bufferView = null);
        needsFlush = false, protectFlush = false, timerId && (clearTimeout(timerId), timerId = null), resume?.(), resume = null;
    };
    const reader = readable.getReader({mode: 'byob'});
    try {
        while (true) {
            if (fastFlush) {
                const {done, value} = await reader.read(new Uint8Array(spareBuffer));
                if (done) break;
                const chunkLen = value.byteLength;
                if (!chunkLen) continue;
                if (chunkLen >= halfChunkLen) {
                    flushDirect(), writable.send(value), spareBuffer = new ArrayBuffer(maxChunkLen);
                } else if (directOff + chunkLen > directBufSize) {
                    flushDirect(), directBuf.set(value, 0), directOff = chunkLen, directTimer = setTimeout(flushDirect, 1), spareBuffer = value.buffer;
                } else {
                    directBuf.set(value, directOff), directOff += chunkLen, directTimer ||= setTimeout(flushDirect, 1), spareBuffer = value.buffer;
                }
                const maxIdx = updateChunkStats(chunkLen, false);
                if (chunkLen < lowerBounds[maxIdx]) {
                    totalBytes = 0;
                } else if ((totalBytes += chunkLen) > startThreshold) {
                    flushDirect(), fastFlush = false, buffer = new ArrayBuffer(bufferSize), bufferView = new Uint8Array(buffer), directBuf = null;
                }
            } else {
                const useSpare = offset > 0 && protectFlush;
                let readBuffer = buffer, readOffset = offset;
                isReading = offset > 0;
                useSpare && (readBuffer = spareBuffer, readOffset = 0, isReading = false);
                const {done, value} = await reader.read(new Uint8Array(readBuffer, readOffset, maxChunkLen));
                isReading = false;
                useSpare ? (bufferView.set(value, offset), spareBuffer = value.buffer) : (buffer = value.buffer, bufferView = new Uint8Array(buffer));
                if (done) break;
                const chunkLen = value.byteLength;
                offset += chunkLen;
                if (needsFlush) {
                    flushBuffer();
                } else {
                    const maxIdx = updateChunkStats(chunkLen, true);
                    if (chunkLen < lowerBounds[maxIdx]) {
                        flushBuffer(), fastFlush = true, totalBytes = 0, directBuf = new Uint8Array(directBufSize), buffer = null, bufferView = null;
                    } else {
                        timerId ||= setTimeout(flushBuffer, flushTime), protectFlush = chunkLen < maxChunkLen;
                        offset > safeBufferSize && await new Promise(r => resume = r);
                    }
                }
            }
        }
    } catch {close?.(), isClose = true} finally {isReading = false, flushDirect(), flushBuffer()}
};