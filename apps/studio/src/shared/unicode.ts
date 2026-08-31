export function hasOnlyUnicodeScalarValues(value: string): boolean {
    for (let index = 0; index < value.length; index += 1) {
        const codeUnit = value.charCodeAt(index);
        if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
            if (index + 1 >= value.length) return false;
            const trailing = value.charCodeAt(index + 1);
            if (trailing < 0xdc00 || trailing > 0xdfff) return false;
            index += 1;
        } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
            return false;
        }
    }
    return true;
}
