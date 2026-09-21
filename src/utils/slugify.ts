import kebabcase from 'lodash.kebabcase';
import slugify from 'slugify';

// eslint-disable-next-line no-control-regex -- \x00-\x7F is the ASCII range, not a stray control char
const hasNonLatin = (str: string): boolean => /[^\x00-\x7F]/.test(str);

/**
 * Slugify a string using a hybrid approach:
 * - Latin strings: slugify (e.g. "E2E Testing" → "e2e-testing")
 * - Strings with non-Latin chars: lodash.kebabcase (preserves non-Latin chars)
 */
export const slugifyStr = (str: string): string => {
    if (hasNonLatin(str)) {
        return kebabcase(str);
    }
    return slugify(str, { lower: true });
};

export const slugifyAll = (arr: string[]) => arr.map((str) => slugifyStr(str));
